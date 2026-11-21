#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mach-O 依赖闭包诊断：install name / LC_LOAD_DYLIB 路径 / rpath / minos。

目的：dyld 报 "Library not loaded" 的表现就是启动即闪退，和签名问题无法从
外观区分。判据是路径字符串逐字节比对，不是"看起来一样"。
"""
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_REQ_DYLD = 0x80000000
NAMES = {
    0xC: "LC_LOAD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0x18 | LC_REQ_DYLD: "LC_LOAD_WEAK_DYLIB",
    0x1F | LC_REQ_DYLD: "LC_REEXPORT_DYLIB",
    0x23 | LC_REQ_DYLD: "LC_LAZY_LOAD_DYLIB",
    0x20 | LC_REQ_DYLD: "LC_LOAD_UPWARD_DYLIB",
    0x1C | LC_REQ_DYLD: "LC_RPATH",
    0x32 | LC_REQ_DYLD: "LC_BUILD_VERSION",
    0x24 | LC_REQ_DYLD: "LC_VERSION_MIN_IPHONEOS",
    0x19: "LC_SEGMENT_64",
    0x1D: "LC_CODE_SIGNATURE",
    0x26: "LC_FUNCTION_STARTS",
    0x29: "LC_DATA_IN_CODE",
    0x80000034: "LC_DYLD_CHAINED_FIXUPS",
    0x80000033: "LC_DYLD_EXPORTS_TRIE",
    0x2: "LC_SYMTAB",
}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def ver(v):
    return f"{v >> 16}.{(v >> 8) & 0xFF}.{v & 0xFF}"


def analyse(path):
    data = open(path, "rb").read()
    print(f"\n=== {path}  ({len(data)} bytes) ===")
    if u32(data, 0) != MH_MAGIC_64:
        print("  !! 不是 MH_MAGIC_64")
        return
    ncmds = u32(data, 16)
    off = 32
    load_dylibs = []
    id_dylib = None
    rpaths = []
    for _ in range(ncmds):
        cmd = u32(data, off)
        cs = u32(data, off + 4)
        if cmd in (0xC, 0xD, 0x18 | LC_REQ_DYLD, 0x1F | LC_REQ_DYLD,
                   0x23 | LC_REQ_DYLD, 0x20 | LC_REQ_DYLD):
            name_off = u32(data, off + 8)
            raw = bytes(data[off + name_off: off + cs]).split(b"\x00")[0].decode("utf-8", "replace")
            if cmd == 0xD:
                id_dylib = raw
                print(f"  [ID_DYLIB] {raw}")
            else:
                load_dylibs.append((NAMES.get(cmd, hex(cmd)), raw))
        elif cmd == 0x1C | LC_REQ_DYLD:
            name_off = u32(data, off + 8)
            raw = bytes(data[off + name_off: off + cs]).split(b"\x00")[0].decode("utf-8", "replace")
            rpaths.append(raw)
        elif cmd == 0x32 | LC_REQ_DYLD:
            platform, minos, sdk = u32(data, off + 8), u32(data, off + 12), u32(data, off + 16)
            plat = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "iOS-sim", 7: "tvOS-sim"}.get(platform, str(platform))
            print(f"  [BUILD_VERSION] platform={plat} minos={ver(minos)} sdk={ver(sdk)}")
        elif cmd == 0x24 | LC_REQ_DYLD:
            print(f"  [VERSION_MIN] minos={ver(u32(data, off + 8))} sdk={ver(u32(data, off + 12))}")
        off += cs

    print(f"  rpath: {rpaths if rpaths else '(无)'}")
    print(f"  依赖 {len(load_dylibs)} 个:")
    for kind, p in load_dylibs:
        print(f"    {kind:<22} {p}")
    return id_dylib, load_dylibs, rpaths


results = {}
for p in sys.argv[1:]:
    results[p] = analyse(p)

# 一致性检查：dylib 的 install name 是否出现在主程序的 LC_LOAD_DYLIB 里
paths = list(results)
if len(paths) == 2:
    a, b = paths
    ida, loadsa, _ = results[a]
    idb, loadsb, _ = results[b]
    print("\n--- 一致性 ---")
    print(f"文件A id={ida}")
    print(f"文件B id={idb}")
    for other, idv, loads in ((b, idb, loadsb), (a, ida, loadsa)):
        pass