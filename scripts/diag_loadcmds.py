#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""列出 movie.orig 全部 load command 类型分布。

目的：chained fixups 的 lib_ordinal 最大到 55，但只数到 42 条 dylib 命令。
dyld 的 ordinal 是按 LC_LOAD_DYLIB / LC_LOAD_WEAK_DYLIB / LC_REEXPORT_DYLIB
/ LC_LOAD_UPWARD_DYLIB 的出现顺序编号的，所以要么我漏数了类型，
要么 ordinal 的语义另有解释。先把事实摆出来。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import inject_dylib as INJ

NAMES = {
    0x1: "LC_SEGMENT", 0x19: "LC_SEGMENT_64", 0x2: "LC_SYMTAB",
    0x3: "LC_SYMSEG", 0x4: "LC_THREAD", 0x5: "LC_UNIXTHREAD",
    0xb: "LC_DYSYMTAB", 0xc: "LC_LOAD_DYLIB", 0xd: "LC_ID_DYLIB",
    0xe: "LC_LOAD_DYLINKER", 0xf: "LC_ID_DYLINKER",
    0x12: "LC_LOAD_DYLIB?", 0x18: "LC_LOAD_WEAK_DYLIB",
    0x1a: "LC_ROUTINES_64", 0x1b: "LC_UUID", 0x1d: "LC_CODE_SIGNATURE",
    0x1e: "LC_SEGMENT_SPLIT_INFO", 0x1f: "LC_REEXPORT_DYLIB",
    0x20: "LC_LAZY_LOAD_DYLIB", 0x21: "LC_ENCRYPTION_INFO",
    0x22: "LC_DYLD_INFO", 0x23: "LC_DYLD_INFO_ONLY",
    0x24: "LC_LOAD_UPWARD_DYLIB", 0x25: "LC_VERSION_MIN_MACOSX",
    0x26: "LC_FUNCTION_STARTS", 0x27: "LC_DYLD_ENVIRONMENT",
    0x29: "LC_DATA_IN_CODE", 0x2a: "LC_SOURCE_VERSION",
    0x2b: "LC_DYLIB_CODE_SIGN_DRS", 0x2c: "LC_ENCRYPTION_INFO_64",
    0x2d: "LC_LINKER_OPTION", 0x2e: "LC_LINKER_OPTIMIZATION_HINT",
    0x2f: "LC_VERSION_MIN_TVOS", 0x30: "LC_VERSION_MIN_WATCHOS",
    0x31: "LC_NOTE", 0x32: "LC_BUILD_VERSION",
    0x80000022: "LC_DYLD_EXPORTS_TRIE", 0x80000023: "LC_DYLD_CHAINED_FIXUPS",
    0x80000033: "LC_DYLD_INFO? ", 0x80000034: "LC_DYLD_CHAINED_FIXUPS",
    0x8000001f: "LC_LOAD_UPWARD?", 0x80000028: "LC_ATOM_INFO",
    0x80000035: "LC_FUNCTION_VARIANTS",
}

DYLIB_KINDS = {0xc, 0xd, 0x18, 0x1f, 0x24, 0x20, 0x8000001f}

p = os.path.join(HERE, "..", "..", "kkys_work", "movie.orig")
with open(p, "rb") as f:
    raw = f.read()
m = INJ.MachO(raw)

from collections import Counter
cnt = Counter()
order = []
off = m.header_size
for _ in range(m.ncmds):
    cmd = INJ.u32(raw, off)
    cs = INJ.u32(raw, off + 4)
    cnt[cmd] += 1
    order.append(cmd)
    off += cs

print(f"ncmds={m.ncmds}  sizeofcmds=0x{m.sizeofcmds:x}\n")
print("命令类型分布：")
for cmd, n in cnt.most_common():
    print(f"  {cmd:#010x} {NAMES.get(cmd, '未知'):26s} × {n}")

dylibs = [c for c in order if c in DYLIB_KINDS]
print(f"\ndylib 类命令（占 ordinal）共 {len(dylibs)} 条")
print(f"按序类型: {[NAMES.get(c, hex(c)) for c in dylibs]}")

# ordinal 1..N 对应的库名（按出现顺序）
print("\nordinal → 库名映射（前 60）：")
idx = 0
off2 = m.header_size
for _ in range(m.ncmds):
    cmd = INJ.u32(raw, off2)
    cs = INJ.u32(raw, off2 + 4)
    if cmd in DYLIB_KINDS:
        idx += 1
        noff = INJ.u32(raw, off2 + 8)
        nm = raw[off2 + noff:off2 + cs].split(b"\x00")[0].decode("utf-8", "replace")
        print(f"  {idx:3d}  {NAMES.get(cmd, hex(cmd)):22s} {nm}")
    off2 += cs
print(f"\n共 {idx} 个 ordinal 槽位")