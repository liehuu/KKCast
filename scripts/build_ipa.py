#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把编译好的 KKCast.dylib 塞进 kkys IPA，输出可直接装的 ipa。

流水线的位置：CI 里 xcodebuild 产出 dylib 之后跑这个。

做的事情，按顺序：
  1. 解包输入的 ipa（原始、未修改的）
  2. 把 dylib 放到 Payload/movie.app/Frameworks/KKCast.dylib
  3. 给 Info.plist 补 NSLocalNetworkUsageDescription
     —— 缺这个键，iOS 14+ 在申请本地网络时直接拒绝，而且**不弹框**，
        表现是 SSDP 一个响应都收不到，看起来像"电视不支持"
  4. 二进制注入 LC_LOAD_DYLIB
  5. 删掉 _CodeSignature（旧签名已经无效，留着会让安装器困惑）
  6. 重新打包

签名不在这里做：TrollStore 安装时会自签，本地没有 ldid 也能出可用包。
"""

import argparse
import os
import plistlib
import shutil
import struct
import subprocess
import sys
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import inject_dylib  # noqa: E402
import adhoc_sign  # noqa: E402


def log(msg):
    print(f"  {msg}")


def find_app_root(unpacked):
    payload = os.path.join(unpacked, "Payload")
    if not os.path.isdir(payload):
        raise SystemExit(f"没有 Payload 目录：{unpacked}")
    for name in os.listdir(payload):
        p = os.path.join(payload, name)
        if p.endswith(".app") and os.path.isdir(p):
            return p
    raise SystemExit("Payload 里没有 .app")


def patch_info_plist(app_dir):
    """补本地网络权限描述。

    必须补的两个理由：
      1. iOS 14 起访问局域网（含 UDP 广播/组播、连局域网 IP）
         需要用户授权，没有描述串时系统直接拒绝且不提示。
      2. 描述串本身是给用户看的，不补的话设置里权限项显示为空白，
         用户不知道这个权限是干嘛的，容易去关掉。
    """
    path = os.path.join(app_dir, "Info.plist")
    with open(path, "rb") as f:
        raw = f.read()
    d = plistlib.loads(raw)

    changed = []

    desc = "用于发现并连接同一 WiFi 下的电视，实现投屏功能。"
    if not d.get("NSLocalNetworkUsageDescription"):
        d["NSLocalNetworkUsageDescription"] = desc
        changed.append("+ NSLocalNetworkUsageDescription")

    # NSBonjourServices 只在用 Bonjour/mDNS 时才需要。
    # DLNA 走 SSDP（UDP 1900 组播），不经过 mDNS，所以不写。
    # 写错反而会让系统在启动时尝试解析这些服务类型。

    # 确保能后台播放：投屏时手机锁屏，App 需要保持存活来转发流
    modes = d.get("UIBackgroundModes") or []
    if isinstance(modes, list):
        # 原来有个空字符串，清掉；空值在某些系统版本上会告警
        modes = [m for m in modes if m]
        if "audio" not in modes:
            modes.append("audio")
            changed.append("+ UIBackgroundModes: audio")
        d["UIBackgroundModes"] = modes

    if changed:
        with open(path, "wb") as f:
            plistlib.dump(d, f, fmt=plistlib.FMT_BINARY)
        for c in changed:
            log(c)
    else:
        log("Info.plist 无需修改")

    return d


def patch_binary(app_dir, dylib_rel):
    exe_name = None
    info_path = os.path.join(app_dir, "Info.plist")
    with open(info_path, "rb") as f:
        info = plistlib.load(f)
    exe_name = info.get("CFBundleExecutable")
    if not exe_name:
        raise SystemExit("Info.plist 里没有 CFBundleExecutable")

    exe_path = os.path.join(app_dir, exe_name)
    if not os.path.isfile(exe_path):
        raise SystemExit(f"可执行文件不存在：{exe_path}")

    with open(exe_path, "rb") as f:
        raw = f.read()

    log(f"原始二进制 {len(raw)} 字节")
    m = inject_dylib.MachO(raw)

    # 幂等：如果已经注入过，就不重复插
    off = m.header_size
    already = False
    for _ in range(m.ncmds):
        cmd = inject_dylib.u32(m.data, off)
        cmdsize = inject_dylib.u32(m.data, off + 4)
        if cmd == inject_dylib.LC_LOAD_DYLIB:
            noff = inject_dylib.u32(m.data, off + 8)
            nm = bytes(m.data[off + noff:off + cmdsize]).split(b"\x00")[0].decode("utf-8", "replace")
            if "KKCast.dylib" in nm:
                already = True
                log(f"已存在注入项：{nm}（跳过）")
        off += cmdsize

    if not already:
        data = inject_dylib.inject_inplace(m, dylib_rel)
        m2 = inject_dylib.MachO(bytes(data))
        data, _ = inject_dylib.strip_codesig(m2)
    else:
        data = bytes(m.data)

    with open(exe_path, "wb") as f:
        f.write(data)
    log(f"注入后 {len(data)} 字节（{len(data) - len(raw):+d}）")
    return exe_path


def remove_codesig(app_dir):
    p = os.path.join(app_dir, "_CodeSignature")
    if os.path.isdir(p):
        shutil.rmtree(p)
        log("已删除 _CodeSignature（旧签名对改动后的内容无效）")


def sign_machos(app_dir, exe_name):
    """给注入后的主程序和 dylib 做 ad-hoc 签名（ldid -S 等价）。

    为什么必须做：
      TrollStore 只绕过安装期证书链校验，dyld 加载每个 image 时仍校验
      cdhash。裸 Mach-O（既无 LC_CODE_SIGNATURE 也无签名 blob）装上去
      点开就 abort。实测 kkys-dlna.ipa 的两个 Mach-O 都是裸的。

    顺序：dylib 先、主程序后；两者互不依赖，但签名必须发生在注入之后、
    重打包之前。签名器自身带 page hash 全量复核，这里再复核一次。
    """
    targets = [
        (os.path.join(app_dir, "Frameworks", "KKCast.dylib"), "KKCast.dylib"),
        (os.path.join(app_dir, exe_name), exe_name),
    ]
    for path, ident in targets:
        if not os.path.isfile(path):
            raise SystemExit(f"签名目标不存在：{path}")
        changed, blob = adhoc_sign.sign_file(path, ident)
        with open(path, "rb") as f:
            data = f.read()
        ok, msg = adhoc_sign.verify_signature(data)
        if not ok:
            raise SystemExit(f"签名后复核失败 {path}: {msg}")
        log(f"签名 {path}（{'新签' if changed else '已签过'}, blob={blob} 字节）✓")


def repack(unpacked, out_ipa, src_ipa=None):
    """重打包成 ipa。

    这里有两个必须继承原包的属性，否则产出的 ipa 装不上或装上就崩：

    1. **Unix 权限位**。`z.write()` 在 Windows 上无法保留 exec 位
       （NTFS 的 ACL 和 Unix mode 不是一回事），实测所有条目都写成
       0o666 —— 主二进制和 dylib 全部没有执行权限。iOS 安装时
       installd 会按该位决定是否 chmod +x，丢掉 exec 位的结果是
       "装上了，点开闪退"，而崩溃日志里看不出任何跟权限有关的线索。

       处理方式：以原 ipa 里同名条目的 external_attr 为准；
       原包里没有的（我们新加的 dylib）按可执行文件写 0o755。

    2. **目录条目**。原包第一条是 `Payload/`，且 SwiftSupport 等
       目录都有显式条目。丢掉目录条目后某些安装器（含 TrollStore 的
       老版本）解包会失败。

    压缩方式也按原条目继承：二进制用 STORED、其余用 DEFLATED，
    这样体积不会因为把已压缩的二进制再压一遍而变大。
    """
    if os.path.exists(out_ipa):
        os.remove(out_ipa)

    # 收集原包的元信息：路径 -> (external_attr, compress_type)
    meta = {}
    if src_ipa and os.path.exists(src_ipa):
        with zipfile.ZipFile(src_ipa) as zs:
            for i in zs.infolist():
                meta[i.filename] = (i.external_attr, i.compress_type)

    # 哪些路径应该是可执行的
    def is_executable(arc):
        base = arc.rsplit("/", 1)[-1]
        if arc.endswith(".dylib") or arc.startswith("SwiftSupport/"):
            return True
        # 主二进制：Payload/Xxx.app/Xxx（深度 3 且无扩展名）
        parts = arc.split("/")
        if len(parts) == 3 and parts[0] == "Payload" and \
                parts[1].endswith(".app") and "." not in base:
            return True
        return False

    written = 0
    # ★ IPA 顶层白名单：只打规范允许的条目。
    #
    # 解包目录里可能混入排查用的中间产物 —— 本次实测 kkys_work/ 里有
    # movie.orig / movie.patched 两份 11MB 的主程序副本和 mp.plist。
    # 整目录递归会把它们一起装进 App：体积 12MB→34MB，而且往 App 里
    # 塞了不该存在的文件。用白名单而不是黑名单，因为黑名单永远漏。
    ALLOWED_TOP = {"Payload", "SwiftSupport", "Symbols", "iTunesMetadata.plist",
                   "iTunesArtwork", "iTunesArtwork@2x", "AssetCatalog.car"}

    def allowed(rel):
        if not rel:
            return True
        return rel.split("/")[0] in ALLOWED_TOP

    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        # 先补目录条目。原包有就原样继承，没有就按 0o755 造。
        dirs = set()
        for dirpath, dirnames, filenames in os.walk(unpacked):
            rel = os.path.relpath(dirpath, unpacked).replace(os.sep, "/")
            if rel == ".":
                continue
            if not allowed(rel):
                dirnames[:] = []
                continue
            dirs.add(rel + "/")
        # 原包里出现过的目录（包括空的）也补上。
        # 但必须跳过已经不存在的目录 —— 最典型的是 _CodeSignature/：
        # 我们已经把磁盘上的目录删了，如果照抄原包的目录条目，就会在
        # 包里留下一个空的 Payload/x.app/_CodeSignature/ 目录。
        # iOS 安装器看到这个目录会认为"有签名但目录是空的"，直接拒绝；
        # 我们的 verify_ipa 也会把它报成残留。
        for name in meta:
            if "/" in name:
                parts = name.split("/")[:-1]
                for k in range(1, len(parts) + 1):
                    d = "/".join(parts[:k]) + "/"
                    # 只保留磁盘上真实存在的目录
                    local = os.path.join(unpacked, d.replace("/", os.sep))
                    if os.path.isdir(local):
                        dirs.add(d)
        for d in sorted(dirs):
            zi = zipfile.ZipInfo(d)
            zi.compress_type = zipfile.ZIP_STORED
            if d in meta:
                zi.external_attr = meta[d][0]
            else:
                zi.external_attr = (0o40755 << 16) | 0x10
            zi.create_system = 3
            z.writestr(zi, b"")
            written += 1

        for dirpath, dirnames, filenames in os.walk(unpacked):
            rel_dir = os.path.relpath(dirpath, unpacked).replace(os.sep, "/")
            if rel_dir != "." and not allowed(rel_dir):
                dirnames[:] = []
                continue
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                arc = os.path.relpath(full, unpacked).replace(os.sep, "/")
                if not allowed(arc):
                    continue

                if arc in meta:
                    ext, ctype = meta[arc]
                else:
                    ext, ctype = None, zipfile.ZIP_DEFLATED

                if ext is None:
                    mode = 0o100755 if is_executable(arc) else 0o100644
                    ext = mode << 16

                zi = zipfile.ZipInfo(arc)
                with open(full, "rb") as f:
                    data = f.read()

                # ★ 压缩方式实测决定，不继承原包、不按类型猜。
                #
                # 原来写的是"继承原条目的 compress_type"，而我的原始包
                # 又是另一个打包脚本产的，两处任何一处判错都会让最终包
                # 翻倍（实测：movie 11441688 字节 STORED vs DEFLATE 后
                # 4590624 字节，差 7MB）。用户反馈"文件比原来大了一倍"
                # 就是这么来的。
                #
                # 现在直接压一遍比大小：变小就用 DEFLATE，没变小
                # （PNG/JPEG/Assets.car 这类已压缩容器）就用 STORED。
                # 判据是产出物实测量，不依赖任何上游假设。
                if data:
                    if len(zlib.compress(data, 6)) < len(data):
                        zi.compress_type = zipfile.ZIP_DEFLATED
                    else:
                        zi.compress_type = zipfile.ZIP_STORED
                else:
                    zi.compress_type = zipfile.ZIP_STORED
                zi.external_attr = ext
                zi.create_system = 3
                zi.date_time = (2020, 1, 1, 0, 0, 0)
                z.writestr(zi, data)
                written += 1

    size = os.path.getsize(out_ipa)
    log(f"输出 {out_ipa}（{size} 字节，{written} 个条目）")
    return size


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ipa", required=True, help="原始 ipa")
    ap.add_argument("--dylib", required=True, help="编译好的 KKCast.dylib")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args()

    work = args.workdir or os.path.join(HERE, "..", ".build", "unpack")
    work = os.path.abspath(work)
    if os.path.isdir(work):
        shutil.rmtree(work)
    os.makedirs(work, exist_ok=True)

    print("[1] 解包")
    with zipfile.ZipFile(args.ipa) as z:
        z.extractall(work)
    app_dir = find_app_root(work)
    log(f"app: {os.path.basename(app_dir)}")

    print("[2] 放入 dylib")
    fw = os.path.join(app_dir, "Frameworks")
    os.makedirs(fw, exist_ok=True)
    dst = os.path.join(fw, "KKCast.dylib")
    shutil.copy2(args.dylib, dst)
    log(f"{os.path.basename(args.dylib)} → Frameworks/（{os.path.getsize(dst)} 字节）")

    print("[3] 补 Info.plist")
    patch_info_plist(app_dir)

    print("[4] 注入 LC_LOAD_DYLIB")
    patch_binary(app_dir, "@executable_path/Frameworks/KKCast.dylib")

    print("[5] 清理旧签名")
    remove_codesig(app_dir)

    print("[6] ad-hoc 签名（ldid -S 等价）")
    with open(os.path.join(app_dir, "Info.plist"), "rb") as f:
        exe_name = plistlib.load(f).get("CFBundleExecutable")
    if not exe_name:
        raise SystemExit("Info.plist 里没有 CFBundleExecutable，无法签名")
    sign_machos(app_dir, exe_name)

    print("[7] 打包")
    repack(work, args.output, src_ipa=args.ipa)

    # 自检：新 ipa 里必须有 dylib 和那条 load command
    print("[8] 自检")
    with zipfile.ZipFile(args.output) as z:
        names = z.namelist()

        # 门禁：包内不得出现 IPA 规范之外的顶层条目。
        # 实测漏过一次：解包目录里留着 movie.orig / movie.patched，
        # 整目录打包把它们塞进了 App 包（体积翻倍 + 多余文件）。
        stray = sorted({n.split("/")[0] for n in names
                        if n.split("/")[0] not in
                        {"Payload", "SwiftSupport", "Symbols", "iTunesMetadata.plist",
                         "iTunesArtwork", "iTunesArtwork@2x", "AssetCatalog.car"}})
        if stray:
            raise SystemExit(f"❌ 包内出现非法顶层条目: {stray}")
        log(f"顶层条目合法，共 {len(names)} 个条目")

        has_dylib = any(n.endswith("Frameworks/KKCast.dylib") for n in names)
        log(f"dylib 在包里: {has_dylib}")
        if not has_dylib:
            raise SystemExit("❌ 打包后找不到 dylib")

        # 不能靠"斜杠数量"猜哪个是可执行文件 —— Payload/movie.app 下有
# Assets.car、Info.plist、PkgInfo 好几个同样深度的文件，猜错就会
# 对着一张 PNG 头去解 load command（struct.error / ncmds 荒谬）。
        # 按 Info.plist 的 CFBundleExecutable 精确取，这是唯一的权威来源。
        plist_name = [n for n in names if n.endswith("/Info.plist") and n.startswith("Payload/")][0]
        with zipfile.ZipFile(args.output) as z2:
            info = plistlib.loads(z2.read(plist_name))
        exe_name = info.get("CFBundleExecutable")
        app_dir_arc = plist_name[: -len("/Info.plist")]
        exe = f"{app_dir_arc}/{exe_name}"
        log(f"可执行文件: {exe}")
        if exe not in names:
            raise SystemExit(f"❌ 包里找不到 {exe}")

        blob = z.read(exe)
        off = 32
        ncmds = struct.unpack("<I", blob[16:20])[0]
        if ncmds <= 0 or ncmds > 2000:
            raise SystemExit(f"❌ 自检读到的 ncmds 不合理：{ncmds}")
        found = False
        for _ in range(ncmds):
            cmd = struct.unpack("<I", blob[off:off + 4])[0]
            cs = struct.unpack("<I", blob[off + 4:off + 8])[0]
            if cmd == inject_dylib.LC_LOAD_DYLIB:
                noff = struct.unpack("<I", blob[off + 8:off + 12])[0]
                nm = blob[off + noff:off + cs].split(b"\x00")[0].decode("utf-8", "replace")
                if "KKCast.dylib" in nm:
                    found = True
            off += cs
        log(f"LC_LOAD_DYLIB(@executable_path/Frameworks/KKCast.dylib) 在包里: {found}")
        if not found:
            raise SystemExit("❌ 打包后找不到注入记录")

    print("\n完成")


if __name__ == "__main__":
    main()