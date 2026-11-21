#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mach-O 架构与平台一致性检查。

为什么这条是决定性的：
  A12 及以上设备（iOS 15+）的 App 二进制是 arm64e。若注入的 dylib 编成
  普通 arm64，dyld 在加载时报 "incompatible architecture" 直接 abort，
  表现就是"装得上、点开闪退"，与签名问题无法从外观区分。
  判据必须读 Mach-O header 的 cpusubtype 原始值，不能看编译器参数。
"""
import struct
import sys

CPU_TYPES = {12: "ARM", 12 | 0x01000000: "ARM64"}
CPU_SUB = {
    0: "ALL",
    1: "V7", 2: "V7S", 3: "V7K", 4: "V6", 5: "V6M", 6: "V7M", 7: "V7EM",
    8: "V8", 9: "V6S", 10: "V9", 11: "V7S", 12: "V8M",
    0: "ALL(arm64)",
}

# arm64e 的 cpu subtype 是 2 | CPU_SUBTYPE_PTRAUTH_ABI(0x80000000)
PTRAUTH_ABI_MASK = 0xFF000000


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def describe_subtype(cputype, sub):
    raw = sub
    sub = sub & 0x00FFFFFF
    ptrauth = raw & PTRAUTH_ABI_MASK
    base = {0: "ALL", 1: "V8", 2: "V8"} .get(sub, f"unknown({sub})")
    if cputype == (12 | 0x01000000):
        names = {0: "arm64 (arm64)", 1: "arm64v8", 2: "arm64e"}
        name = names.get(sub, f"arm64-sub{sub}")
        if ptrauth:
            name += f" [ptrauth ABI v{ptrauth >> 24}]"
        return name, sub, ptrauth
    return base, sub, ptrauth


def check(path):
    data = open(path, "rb").read()
    magic = u32(data, 0)
    print(f"\n=== {path} ===")
    if magic in (0xCAFEBABE, 0xCAFEBABF):
        print("  FAT binary (多架构)，需逐 slice 检查")
        n = struct.unpack_from(">I", data, 4)[0]
        for i in range(n):
            cputype, cpusub, offset, size, align = struct.unpack_from(">IIIII", data, 8 + i * 20)
            nm, sub, pt = describe_subtype(cputype, cpusub)
            print(f"   slice[{i}] cputype=0x{cputype:x} cpusubtype_raw=0x{cpusub:08x} "
                  f"→ {nm}  off={offset} size={size}")
        return
    if magic != 0xFEEDFACF:
        print(f"  !! magic=0x{magic:08x} 不是 MH_MAGIC_64")
        return
    cputype = u32(data, 4)
    cpusub_raw = u32(data, 8)
    filetype = u32(data, 12)
    nm, sub, pt = describe_subtype(cputype, cpusub_raw)
    ft = {2: "MH_EXECUTE", 6: "MH_DYLIB", 8: "MH_BUNDLE"}.get(filetype, str(filetype))
    print(f"  magic=MH_MAGIC_64  filetype={ft}")
    print(f"  cputype=0x{cputype:x}  cpusubtype_raw=0x{cpusub_raw:08x}")
    print(f"  → 架构: {nm}")
    # 平台 / minos
    ncmds, off = u32(data, 16), 32
    for _ in range(ncmds):
        cmd, cs = u32(data, off), u32(data, off + 4)
        if cmd == 0x32 | 0x80000000:      # LC_BUILD_VERSION
            plat, minos, sdk = u32(data, off + 8), u32(data, off + 12), u32(data, off + 16)
            pn = {1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 6: "iOS-simulator",
                  7: "tvOS-simulator"}.get(plat, str(plat))
            print(f"  LC_BUILD_VERSION platform={pn} minos={minos>>16}.{(minos>>8)&0xFF}.{minos&0xFF} "
                  f"sdk={sdk>>16}.{(sdk>>8)&0xFF}.{sdk&0xFF}")
        elif cmd == 0x24 | 0x80000000:    # LC_VERSION_MIN_IPHONEOS
            minos, sdk = u32(data, off + 8), u32(data, off + 12)
            print(f"  LC_VERSION_MIN_IPHONEOS minos={minos>>16}.{(minos>>8)&0xFF}.{minos&0xFF}")
        off += cs
    return dict(cputype=cputype, cpusub_raw=cpusub_raw, name=nm)


res = {}
for p in sys.argv[1:]:
    res[p] = check(p)

if len(res) >= 2:
    print("\n--- 架构一致性（决定性判据）---")
    items = [(p, r) for p, r in res.items() if r]
    execs = [(p, r) for p, r in items if "movie" in p or p.endswith("movie")]
    bad = 0
    for p, r in items:
        for pe, re_ in items:
            if p == pe:
                continue
            if r["cputype"] != re_["cputype"]:
                print(f"  ✗ {p} cputype=0x{r['cputype']:x} != {pe} 0x{re_['cputype']:x}")
                bad += 1
            elif r["cpusub_raw"] != re_["cpusub_raw"]:
                print(f"  ✗ {p.split('/')[-1]:<20} cpusubtype_raw=0x{r['cpusub_raw']:08x} ({r['name']})"
                      f"  !=  {pe.split('/')[-1]:<20} 0x{re_['cpusub_raw']:08x} ({re_['name']})")
                bad += 1
    if not bad:
        print("  ✓ 全部一致")