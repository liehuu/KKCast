#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统计主程序的依赖库数量，并核对 chained fixups 里实际出现的 lib_ordinal 范围。

用途：F6 判据里我硬编码了 `1 <= lib <= 40`，实测报 lib_ordinal=41。
先问清楚：是这个 App 真的有 41+ 个依赖，还是位域解错了？
  - 若 LC_LOAD_DYLIB 条目数 > 40 → 判据写错了，改成「按实际依赖数动态取上界」。
  - 若依赖库很少却出现 41 → 位域解错了，得回去查 imports_format。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import inject_dylib as INJ

DYLIB_CMDS = {
    0xC: "LC_LOAD_DYLIB",
    0x8000001F: "LC_LOAD_UPWARD_DYLIB",
    0xD: "LC_ID_DYLIB",
    0x18: "LC_LOAD_WEAK_DYLIB",
    0x1F: "LC_REEXPORT_DYLIB",
}

with open(os.path.join(HERE, "..", "..", "kkys_work", "movie.orig"), "rb") as f:
    raw = f.read()

m = INJ.MachO(raw)
print(f"ncmds={m.ncmds}  sizeofcmds=0x{m.sizeofcmds:x}  文件 {len(raw)} 字节\n")

deps = []
off = m.header_size
for _ in range(m.ncmds):
    cmd = INJ.u32(raw, off)
    cs = INJ.u32(raw, off + 4)
    if cmd in DYLIB_CMDS:
        noff = INJ.u32(raw, off + 8)
        nm = raw[off + noff:off + cs].split(b"\x00")[0].decode("utf-8", "replace")
        deps.append((DYLIB_CMDS[cmd], nm))
    off += cs

print(f"依赖库命令共 {len(deps)} 条：")
for i, (kind, nm) in enumerate(deps, 1):
    print(f"  #{i:2d} {kind:22s} {nm}")

# 找 CHAINED_FIXUPS
dataoff = datasize = None
off = m.header_size
for _ in range(m.ncmds):
    cmd = INJ.u32(raw, off)
    cs = INJ.u32(raw, off + 4)
    if cmd == 0x80000034:
        dataoff = INJ.u32(raw, off + 8)
        datasize = INJ.u32(raw, off + 12)
    off += cs

if dataoff is None:
    print("\n没有 LC_DYLD_CHAINED_FIXUPS")
    sys.exit(0)

blob = raw[dataoff:dataoff + datasize]
ver, st, imp, sym, cnt, ifmt, sfmt = __import__("struct").unpack("<7I", blob[:28])
print(f"\nCHAINED_FIXUPS @0x{dataoff:x} size={datasize}")
print(f"  fixups_version={ver} starts={st} imports={imp} symbols={sym}")
print(f"  imports_count={cnt} imports_format={ifmt} symbols_format={sfmt}")

if ifmt != 1:
    print(f"\nimports_format={ifmt}，不是 1，不做位域解析")
    sys.exit(0)

base = dataoff + imp
ords = {}
bad = []
sym_base = dataoff + sym
for i in range(cnt):
    v = INJ.u32(raw, base + i * 4)
    lib = v & 0xFF
    weak = (v >> 8) & 1
    noff = v >> 9
    ords[lib] = ords.get(lib, 0) + 1
    nm_end = raw.find(b"\x00", sym_base + noff)
    nm = raw[sym_base + noff:nm_end].decode("utf-8", "replace") if nm_end > 0 else "?"
    if lib not in (0, 0xFE, 0xFF) and lib > len(deps):
        bad.append((i, lib, noff, weak, nm))

print(f"\nlib_ordinal 分布（共 {cnt} 条导入）：")
for lib in sorted(ords):
    tag = {0: "自身", 0xFE: "flat-namespace", 0xFF: "主程序"}.get(lib, f"依赖 #{lib}")
    print(f"  ordinal {lib:3d} ({tag:14s}): {ords[lib]:5d} 条")

print(f"\n依赖库总数 = {len(deps)}；出现过的最大 ordinal = {max(ords)}")
if bad:
    print(f"\n越界导入 {len(bad)} 条（前 10）：")
    for i, lib, noff, weak, nm in bad[:10]:
        print(f"  #{i} lib={lib} name_off={noff} weak={weak} {nm}")
else:
    print("\n全部 ordinal 均在依赖库范围内 ✅")