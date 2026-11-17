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

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import inject_dylib  # noqa: E402


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


def repack(unpacked, out_ipa):
    if os.path.exists(out_ipa):
        os.remove(out_ipa)

    # 用 ZIP_DEFLATED，但二进制本身已压缩过，用 STORED 更快也更小概率出错。
    # 这里统一 DEFLATED：iOS 安装器两种都认。
    with zipfile.ZipFile(out_ipa, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for dirpath, dirnames, filenames in os.walk(unpacked):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                arc = os.path.relpath(full, unpacked).replace(os.sep, "/")
                z.write(full, arc)
    size = os.path.getsize(out_ipa)
    log(f"输出 {out_ipa}（{size} 字节）")
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

    print("[6] 打包")
    repack(work, args.output)

    # 自检：新 ipa 里必须有 dylib 和那条 load command
    print("[7] 自检")
    with zipfile.ZipFile(args.output) as z:
        names = z.namelist()
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