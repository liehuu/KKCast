#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""核对 chained fixups 导入表的位域解析，并回答一个关键问题：

  原始未注入的 movie.orig 里，lib_ordinal 就已经超过 LC_LOAD_DYLIB 条数
  （42）了吗？

若是，则"导入表绝对合法"不能作为注入工具的判据 —— 那是原样本的既有
特征，注入既不产生也不修复它。正确的判据只能是"注入前后完全一致"。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import inject_dylib as INJ

p = os.path.join(HERE, "..", "..", "kkys_work", "movie.orig")
with open(p, "rb") as f:
    raw = f.read()

m = INJ.MachO(raw)

# 数依赖库
deps = []
off = m.header_size
for _ in range(m.ncmds):
    cmd = INJ.u32(raw, off)
    cs = INJ.u32(raw, off + 4)
    if cmd in (0xC, 0xD, 0x18, 0x1F, 0x8000001F):
        deps.append(cmd)
    off += cs
print(f"依赖库命令 {len(deps)} 条")

# 找 CHAINED_FIXUPS
dataoff = datasize = None
off = m.header_size
for _ in range(m.ncmds):
    if INJ.u32(raw, off) == 0x80000034:
        dataoff = INJ.u32(raw, off + 8)
        datasize = INJ.u32(raw, off + 12)
    off += INJ.u32(raw, off + 4)

blob = raw[dataoff:dataoff + datasize]
ver, st, imp, sym, cnt, ifmt, sfmt = struct.unpack("<7I", blob[:28])
print(f"fixups @0x{dataoff:x} ver={ver} starts={st} imports={imp} "
      f"symbols={sym} count={cnt} ifmt={ifmt} sfmt={sfmt}")

base = dataoff + imp
sym_base = dataoff + sym
sym_pool_len = len(blob) - sym

print(f"\n前 6 条原始 32bit 值（十六进制）与逐位拆解：")
for i in range(6):
    v = INJ.u32(raw, base + i * 4)
    lib = v & 0xFF
    weak = (v >> 8) & 1
    noff = v >> 9
    e = raw.find(b"\x00", sym_base + noff)
    nm = raw[sym_base + noff:e].decode("utf-8", "replace") if 0 < e < len(raw) else "?"
    lo8 = v & 0xFF
    b8 = (v >> 8) & 1
    hi23 = v >> 9
    print(f"  #{i}: v=0x{v:08x}  lib={lib:3d} weak={weak} name_off={noff:6d}  "
          f"校验: (0x{v:08x} & 0xff)={lo8} ((v>>8)&1)={b8} (v>>9)={hi23}")
    print(f"       符号: {nm[:70]}")

print(f"\nsymbols 池长 {sym_pool_len}，最大 name_offset 应为 < {sym_pool_len}")

# 全量：ordinal 越界统计
over = 0
max_o = 0
for i in range(cnt):
    v = INJ.u32(raw, base + i * 4)
    lib = v & 0xFF
    if lib not in (0, 0xFE, 0xFF, 0xFD):
        max_o = max(max_o, lib)
        if lib > len(deps):
            over += 1
print(f"ordinal 越界 {over}/{cnt} 条，最大 ordinal = {max_o}，依赖数 = {len(deps)}")

# 交叉验证：用 8 字节步长解一遍，看哪种解释更自洽
print("\n【交叉验证】若按 8 字节步长解（另一种对齐假设）：")
bad8 = 0
for i in range(min(cnt, 3249)):
    off_i = base + i * 8
    if off_i + 8 > dataoff + datasize:
        break
    v = INJ.u32(raw, off_i)
    lib = v & 0xFF
    noff = v >> 9
    if lib not in (0, 0xFE, 0xFF, 0xFD) and (lib > len(deps) or noff >= sym_pool_len):
        bad8 += 1
print(f"  异常条数（4 字节步长）= {over}")
print(f"  异常条数（8 字节步长）= {bad8}（取小者为正确解释）")