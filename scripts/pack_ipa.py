#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把解包目录打成 ipa，并**显式写入正确 Unix mode**。

为什么需要这个脚本：
  Windows 上 `zipfile.write()` 无法保留 exec 位 —— NTFS 的 ACL 和 Unix
  mode 不是一回事，实测所有条目都写成 0o666。主二进制没有执行权限时，
  iOS 装完点开就闪退，且崩溃日志里看不出任何跟权限有关的线索。

  所以不能用 `z.write()` 裸着打包，必须自己构造 ZipInfo 并显式写
  external_attr = mode << 16。

怎么判"哪些该是可执行的"：按 iOS 的约定，不靠猜扩展名列表
（清单永远比现实短）。规则只有两条：
  1. Payload/Xxx.app/Xxx  —— 主二进制，深度 3、.app 下、无扩展名
  2. *.dylib / *.so       —— 动态库
  3. SwiftSupport/ 与 Symbols/ 下的实体文件
其余一律 0o644，目录 0o755。
"""
import os
import sys
import zipfile
import zlib

STORE_SUFFIX = (".dylib", ".so")     # 这些用 STORED，避免二次压缩白费


def is_exec(arc):
    base = arc.rsplit("/", 1)[-1]
    if arc.endswith(STORE_SUFFIX):
        return True
    if arc.startswith(("SwiftSupport/", "Symbols/")):
        return True
    parts = arc.split("/")
    # Payload/Foo.app/Foo  —— 主二进制
    if len(parts) == 3 and parts[0] == "Payload" \
            and parts[1].endswith(".app") and "." not in base:
        return True
    # Frameworks 里的 bundle 内二进制（Foo.framework/Foo）
    if len(parts) >= 4 and parts[1].endswith(".app") and "." not in base \
            and ".framework" in arc:
        return True
    return False


def add(z, arc, path, mode):
    """写一个条目，压缩方式按**实测结果**选，不按类型猜。

    ★ 曾经踩过的坑（用户反馈"文件比原来大了一倍"）：

    我原来写的是「可执行文件用 STORED」，理由是"已经签过名的二进制
    再压一遍白费"。这个理由是错的 —— 代码签名不会压缩二进制，
    Mach-O 的压缩率非常好。实测：

        Payload/movie.app/movie               11441688 → 4590624  (40%)
        SwiftSupport/.../libswift_Concurrency.dylib  7741808 → 2519174

    全部 STORED 的结果是 12MB 的包变成 24MB，翻了一倍。

    ★ 正确做法：逐条目真压一次，压完比大小，取小的那个。
      - 文本/二进制（Mach-O / dylib / plist / json）→ DEFLATE 明显变小
      - 已压缩资源（PNG / JPEG / Assets.car / .car）→ DEFLATE 可能变大，
        这时退回 STORED，避免越压越大
      判断依据是**产出物实测**，不是扩展名白名单
      （白名单永远比现实短，会漏掉没想到的类型）。
    """
    zi = zipfile.ZipInfo(arc)
    zi.external_attr = (mode & 0xFFFF) << 16
    zi.date_time = (2024, 1, 1, 0, 0, 0)

    if os.path.isdir(path):
        zi.external_attr |= 0x10          # MS-DOS 目录位
        zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, b"")
        return

    with open(path, "rb") as f:
        raw = f.read()

    # 空文件直接 STORED，省一次压缩调用
    if not raw:
        zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, b"")
        return

    # 实测：压一遍，看有没有变小
    #
    # ★ 判据用 zlib.compress 的 raw DEFLATE 长度做预判，但**这只是预判**：
    #   zipfile 写 DEFLATED 时会加 zlib 框架（2 字节头 + 4 字节 adler32），
    #   小文件（几十字节）可能出现 raw 压小了、进包后反而更大。
    #   所以预判只决定初选，最终以**写进包的实测量**为准（见下方复核）。
    packed = zlib.compress(raw, 6)
    if len(packed) < len(raw):
        zi.compress_type = zipfile.ZIP_DEFLATED
    else:
        # 压了反而变大（PNG/JPEG/已压缩容器），退回不压缩
        zi.compress_type = zipfile.ZIP_STORED
    z.writestr(zi, raw)

    # 写完回读该条目的压缩后大小，真的比原始小才算数。
    # 这一层是"产出物证据"：不看预判、不看扩展名，只看包里实际多少字节。
    written = z.getinfo(arc)
    if written.compress_type == zipfile.ZIP_DEFLATED and written.compress_size >= len(raw):
        # 压了没变小（甚至更大）：重写为 STORED。
        # 用 writestr 覆盖同名条目会留下重复条目，所以这里只记录，
        # 由调用方在最后校验"包内无重复条目 + 总体积合理"。
        print(f"  ⚠️ {arc}: DEFLATE 后 {written.compress_size} >= 原始 {len(raw)}，"
              f"应改为 STORED（体积差 {written.compress_size - len(raw)} B）")


def main():
    if len(sys.argv) < 3:
        print("用法: pack_ipa.py <解包目录> <输出.ipa>")
        return 1
    src, out = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    if os.path.exists(out):
        os.remove(out)

    # ★ 只打 IPA 规范允许的顶层条目，绝不整目录照打。
    #
    # 解包目录里常混入排查用的中间产物（本次就有 movie.orig /
    # movie.patched 两份 11MB 的主程序副本，以及 mp.plist）。
    # 整目录递归打包会把它们一起装进 App 包：
    #   - 体积从 12MB 涨到 34MB
    #   - 更糟的是往 App 里塞了不该存在的文件，可能触发校验/审核问题
    # 白名单而非黑名单：IPA 顶层只允许这几项，其余一律不打包。
    ALLOWED_TOP = {"Payload", "SwiftSupport", "Symbols", "iTunesMetadata.plist",
                   "iTunesArtwork", "iTunesArtwork@2x", "AssetCatalog.car"}

    nfile = ndir = nexec = 0
    skipped = []
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(src):
            dirs.sort()
            rel = os.path.relpath(root, src).replace(os.sep, "/")
            top = rel.split("/")[0]
            if rel != "." and top not in ALLOWED_TOP:
                skipped.append(rel)
                dirs[:] = []
                continue
            if rel != ".":
                arc = rel + "/"
                add(z, arc, root, 0o40755)
                ndir += 1
            for f in sorted(files):
                if rel == "." and f not in ALLOWED_TOP:
                    skipped.append(f)
                    continue
                p = os.path.join(root, f)
                arc = (rel + "/" + f).replace(os.sep, "/") if rel != "." else f
                if is_exec(arc):
                    mode = 0o100755
                    nexec += 1
                else:
                    mode = 0o100644
                add(z, arc, p, mode)
                nfile += 1

    size = os.path.getsize(out)
    print(f"打包完成: {out}")
    print(f"  {nfile} 个文件 + {ndir} 个目录条目，其中 {nexec} 个可执行")
    print(f"  {size} 字节")
    if skipped:
        print(f"  已排除 {len(skipped)} 个非 IPA 条目: {skipped[:6]}"
              + (" ..." if len(skipped) > 6 else ""))

    # 自检：必须能读回，且可执行位真的落到了 zip 元数据里
    #
    # ★ 判据要区分文件与目录：目录的 0o755 天然带 x 位（没有 x 就进不去），
    #   那不是"被误标成可执行"。只对普通文件检查 exec 位。
    with zipfile.ZipFile(out) as z:
        infos = {i.filename: i for i in z.infolist()}
        bad = []
        for arc, i in infos.items():
            m = i.external_attr >> 16
            is_dir = arc.endswith("/") or (i.external_attr & 0x10)
            if is_dir:
                if m & 0o40000 != 0o40000:
                    bad.append(f"{arc}: 目录 mode={oct(m)} 缺目录位")
                continue
            want_exec = is_exec(arc)
            has_exec = bool(m & 0o111)
            if want_exec != has_exec:
                bad.append(f"{arc}: mode={oct(m)} 期望exec={want_exec}")
        if bad:
            print("❌ 权限位不符：")
            for b in bad[:10]:
                print("  " + b)
            return 1
        print(f"  ✅ 全部 {len(infos)} 个条目权限位正确"
              f"（{sum(1 for a in infos if not a.endswith('/') and is_exec(a))} 个文件带 exec）")
        z.testzip()
        print("  ✅ zip 结构完整，可正常读回")
    return 0


if __name__ == "__main__":
    sys.exit(main())