#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验最终 ipa：改动是否真的在包里。

这一层和前面几层的区别：
  门禁 1~3 校验的是**源文件和中间产物**。它们全绿，也不代表
  最终 zip 里装的是那个产物。UnCast 那次就是靠"产物差分"才发现
  某处修改没进包——CI 全绿，装到电视上却没有那个行为。

  所以这里只认最终 ipa 里的字节，不认任何构建声明。

判定项：
  A. dylib 存在且大小 > 1KB（不是空壳）
  B. dylib 本身是合法 arm64 MH_DYLIB（不是误拷了别的架构）
  C. 可执行文件里有 LC_LOAD_DYLIB 指向我们的 dylib
  D. 可执行文件里**没有** LC_CODE_SIGNATURE（残留会让安装器按
     旧签名校验新内容，直接拒装）
  E. Info.plist 有 NSLocalNetworkUsageDescription 且非空
  F. _CodeSignature 目录已删除
  G. 可执行文件的 __LINKEDIT 仍完整（截断没截过头）
"""

import os
import plistlib
import struct
import sys
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_BUILD_VERSION = 0x32

FAIL = []


def fail(m):
    FAIL.append(m)
    print(f"  ❌ {m}")


def ok(m):
    print(f"  ✅ {m}")


def u32(b, o):
    return struct.unpack("<I", b[o:o + 4])[0]


def u64(b, o):
    return struct.unpack("<Q", b[o:o + 8])[0]


def main():
    if len(sys.argv) < 2:
        raise SystemExit("用法: verify_ipa.py <ipa>")
    ipa = sys.argv[1]
    print(f"文件: {ipa}  ({os.path.getsize(ipa)} 字节)")
    print()

    z = zipfile.ZipFile(ipa)
    names = z.namelist()

    # A. dylib 存在
    dylibs = [n for n in names if n.endswith("Frameworks/KKCast.dylib")]
    if not dylibs:
        fail("包里没有 Frameworks/KKCast.dylib")
        print("\n结论：FAIL")
        return 1
    info = z.getinfo(dylibs[0])
    if info.file_size < 1024:
        fail(f"dylib 只有 {info.file_size} 字节，像是空壳")
    else:
        ok(f"dylib 存在，{info.file_size} 字节")

    # B. dylib 是合法 arm64
    db = z.read(dylibs[0])
    if u32(db, 0) != MH_MAGIC_64:
        fail(f"dylib magic=0x{u32(db,0):08x}，不是 MH_MAGIC_64")
    elif u32(db, 4) != CPU_TYPE_ARM64:
        fail(f"dylib cputype=0x{u32(db,4):08x}，不是 arm64")
    elif u32(db, 12) != 6:
        fail(f"dylib filetype={u32(db,12)}，不是 MH_DYLIB(6)")
    else:
        ok("dylib 是 arm64 MH_DYLIB")

    # 找可执行文件：用 Info.plist 的 CFBundleExecutable，别猜
    plists = [n for n in names if n.endswith(".app/Info.plist") and n.startswith("Payload/")]
    if not plists:
        fail("包里没有 Payload/*.app/Info.plist")
        print("\n结论：FAIL")
        return 1
    plist_name = plists[0]
    app_arc = plist_name[: -len("/Info.plist")]
    pdata = plistlib.loads(z.read(plist_name))
    exe_name = pdata.get("CFBundleExecutable")
    exe_arc = f"{app_arc}/{exe_name}"
    if exe_arc not in names:
        fail(f"找不到可执行文件 {exe_arc}")
        print("\n结论：FAIL")
        return 1

    blob = z.read(exe_arc)
    ok(f"可执行文件 {exe_arc}，{len(blob)} 字节")

    # C/D/G：遍历 load command
    if u32(blob, 0) != MH_MAGIC_64:
        fail(f"可执行文件 magic=0x{u32(blob,0):08x} 不对")
        print("\n结论：FAIL")
        return 1

    ncmds = u32(blob, 16)
    sizeofcmds = u32(blob, 20)
    off = 32
    found_dylib = False
    found_codesig = False
    linkedit = None
    platform = None

    for _ in range(ncmds):
        if off + 8 > len(blob):
            fail(f"load command 越界 @ {off}")
            break
        cmd = u32(blob, off)
        cs = u32(blob, off + 4)
        if cs < 8:
            fail(f"cmdsize 异常 {cs} @ {off}")
            break
        if cmd == LC_LOAD_DYLIB:
            noff = u32(blob, off + 8)
            nm = blob[off + noff:off + cs].split(b"\x00")[0].decode("utf-8", "replace")
            if "KKCast.dylib" in nm:
                found_dylib = True
                ok(f"LC_LOAD_DYLIB → {nm}")
        elif cmd == LC_CODE_SIGNATURE:
            found_codesig = True
        elif cmd == LC_SEGMENT_64:
            sname = blob[off + 8:off + 24].split(b"\x00")[0].decode("ascii", "replace")
            fileoff = u64(blob, off + 40)
            filesize = u64(blob, off + 48)
            if sname == "__LINKEDIT":
                linkedit = (fileoff, filesize)
        elif cmd == LC_BUILD_VERSION:
            platform = u32(blob, off + 8)
        off += cs

    if not found_dylib:
        fail("可执行文件里没有指向 KKCast.dylib 的 LC_LOAD_DYLIB —— 注入没生效")
    if found_codesig:
        fail("可执行文件残留 LC_CODE_SIGNATURE —— 安装器会按旧签名校验新内容而拒装")
    else:
        ok("无 LC_CODE_SIGNATURE 残留")

    # load command 链必须正好结束在 header 声明的位置
    expected_end = 32 + sizeofcmds
    if off != expected_end:
        fail(f"load command 链结束于 {off}，header 声明 {expected_end} —— 结构不自洽")
    else:
        ok(f"load command 链完整（ncmds={ncmds}, sizeofcmds=0x{sizeofcmds:x}）")

    if platform == 2:
        ok("可执行文件 platform=iOS")
    else:
        fail(f"可执行文件 platform={platform}，不是 iOS(2)")

    # G. __LINKEDIT 不能越界
    if linkedit:
        fend = linkedit[0] + linkedit[1]
        if fend > len(blob):
            fail(f"__LINKEDIT 结束于 {fend}，超过文件长度 {len(blob)} —— 截断出错")
        else:
            ok(f"__LINKEDIT 完整（结束于 {fend}，文件 {len(blob)}）")

    # E. Info.plist 本地网络权限
    desc = pdata.get("NSLocalNetworkUsageDescription")
    if desc and isinstance(desc, str) and desc.strip():
        ok(f"NSLocalNetworkUsageDescription: {desc}")
    else:
        fail("缺 NSLocalNetworkUsageDescription —— iOS 14+ 会静默拒绝局域网访问")

    # F. 旧签名目录
    sig = [n for n in names if "_CodeSignature/" in n]
    if sig:
        fail(f"残留 _CodeSignature {len(sig)} 个文件")
    else:
        ok("_CodeSignature 已清理")

    # 附加：确认原有资源没被破坏（防止解包/重打包丢文件）
    must_keep = [
        f"{app_arc}/Assets.car",
        f"{app_arc}/PkgInfo",
    ]
    for m in must_keep:
        if m in names:
            ok(f"原有资源保留: {os.path.basename(m)}")
        else:
            fail(f"原有资源丢失: {m}")

    print()
    if FAIL:
        print(f"结论：FAIL（{len(FAIL)} 项）")
        return 1
    print("结论：PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())