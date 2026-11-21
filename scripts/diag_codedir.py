#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CodeDirectory 完整字段解析 —— 按 version 决定 header 长度。

为什么这是决定性的：
  Apple CodeDirectory 的 header 长度**依赖 version 字段**，不是固定值：
    0..43     固定 44 字节（所有版本）
    >=0x20100 +4   scatterOffset
    >=0x20200 +4   teamOffset
    >=0x20300 +8   spare3 + codeLimit64
    >=0x20400 +24  execSegBase/execSegLimit/execSegFlags
    >=0x20500 +8   runtime + preEncryptOffset
  version=0x20400 的 header 应是 92 字节。
  若按 44 字节写 identOffset/hashOffset，hash 表整体前移 48 字节，
  CodeDirectory.length 与实际不符 —— iOS 读 hash 时全部错位。
  而"自己算 hash 自己验"的检查永远通过，因为读写用的是同一个错值。
"""
import struct
import sys

CSMAGIC_CODEDIRECTORY = 0xFADE0C02
LC_CODE_SIGNATURE = 0x1D


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def bu32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def bu64(b, o):
    return struct.unpack_from(">Q", b, o)[0]


def header_len(version):
    """按 version 计算 CodeDirectory 固定头长度。"""
    n = 44
    if version >= 0x20100:
        n += 4          # scatterOffset
    if version >= 0x20200:
        n += 4          # teamOffset
    if version >= 0x20300:
        n += 8          # spare3(4) + codeLimit64(8) 实际是 4+8=12？
    if version >= 0x20400:
        n += 24
    if version >= 0x20500:
        n += 8
    return n


def header_len_exact(version):
    """精确版：按 Apple 的 CodeDirectory 定义逐字段累加。

    字段顺序（CS_CodeDirectory struct）：
      magic, length, version, flags, hashOffset, identOffset,
      nSpecialSlots, nCodeSlots, codeLimit, hashSize, hashType, platform,
      pageSize, spare2,
      [>=0x20100] scatterOffset,
      [>=0x20200] teamOffset,
      [>=0x20300] spare3, codeLimit64,
      [>=0x20400] execSegBase(8), execSegLimit(8), execSegFlags(8),
      [>=0x20500] runtime, preEncryptOffset
    """
    n = 44
    if version >= 0x20100:
        n += 4
    if version >= 0x20200:
        n += 4
    if version >= 0x20300:
        n += 4 + 8      # spare3(4) + codeLimit64(8)
    if version >= 0x20400:
        n += 8 + 8 + 8  # execSegBase + execSegLimit + execSegFlags
    if version >= 0x20500:
        n += 4 + 4      # runtime + preEncryptOffset
    return n


def find_codesig(data):
    ncmds, off = u32(data, 16), 32
    for _ in range(ncmds):
        cmd, cs = u32(data, off), u32(data, off + 4)
        if cmd == LC_CODE_SIGNATURE:
            return u32(data, off + 8), u32(data, off + 12)
        off += cs
    return None, None


def parse(path):
    data = open(path, "rb").read()
    do, ds = find_codesig(data)
    print(f"\n=== {path} ===")
    if do is None:
        print("  !! 无 LC_CODE_SIGNATURE")
        return
    blob = data[do:do + ds]
    _, slen, count = struct.unpack_from(">III", blob, 0)
    cds = [(t, o) for t, o in (struct.unpack_from(">II", blob, 12 + 8 * i) for i in range(count)) if t == 0]
    assert len(cds) == 1, cds
    cd = blob[cds[0][1]:]
    magic, length = struct.unpack_from(">II", cd, 0)
    version = bu32(cd, 8)
    flags = bu32(cd, 12)
    hash_off = bu32(cd, 16)
    ident_off = bu32(cd, 20)
    nsp = bu32(cd, 24)
    ncs = bu32(cd, 28)
    code_limit = bu32(cd, 32)
    hs, ht, plat, psz = struct.unpack_from(">BBBB", cd, 36)
    spare2 = bu32(cd, 40)

    print(f"  magic=0x{magic:08x} (CodeDirectory={magic == CSMAGIC_CODEDIRECTORY})")
    print(f"  length={length}")
    print(f"  version=0x{version:x}  → 应为 {version >> 16}.{(version >> 8) & 0xFF}.{version & 0xFF}")
    print(f"  flags=0x{flags:x}")
    print(f"  hashOffset={hash_off}   identOffset={ident_off}")
    print(f"  nSpecialSlots={nsp}  nCodeSlots={ncs}  codeLimit={code_limit}")
    print(f"  hashSize={hs}  hashType={ht}  platform={plat}  pageSize=2^{psz}  spare2={spare2}")

    hl = header_len_exact(version)
    print(f"\n  ★ 按 version=0x{version:x} 计算的 header 长度 = {hl}")
    print(f"  ★ 实际 identOffset = {ident_off}   "
          f"{'一致 ✓' if ident_off == hl else '不一致 ✗'}")
    if ident_off != hl:
        print(f"     差 {ident_off - hl} 字节")

    # 逐字段读可选部分
    p = 44
    if version >= 0x20100:
        print(f"  [+44] scatterOffset = {bu32(cd, p)}"); p += 4
    if version >= 0x20200:
        print(f"  [+{p}] teamOffset = {bu32(cd, p)}"); p += 4
    if version >= 0x20300:
        print(f"  [+{p}] spare3 = {bu32(cd, p)}"); p += 4
        print(f"  [+{p}] codeLimit64 = {bu64(cd, p)}"); p += 8
    if version >= 0x20400:
        print(f"  [+{p}] execSegBase  = 0x{bu64(cd, p):x}"); p += 8
        print(f"  [+{p}] execSegLimit = 0x{bu64(cd, p):x}"); p += 8
        print(f"  [+{p}] execSegFlags = 0x{bu64(cd, p):x}"); p += 8
    if version >= 0x20500:
        print(f"  [+{p}] runtime = {bu32(cd, p)}"); p += 4
        print(f"  [+{p}] preEncryptOffset = {bu32(cd, p)}"); p += 4
    print(f"  可选字段终点 = {p}  (应等于 identOffset={ident_off})")

    # ident 与 hash 区
    if ident_off < len(cd):
        ident = cd[ident_off:].split(b"\x00")[0]
        print(f"\n  identifier = {ident.decode('utf-8', 'replace')}  (长度 {len(ident)+1} 含 NUL)")
        expect_hash_off = ident_off + len(ident) + 1
        print(f"  推算 hashOffset = {ident_off} + {len(ident)+1} = {expect_hash_off}   "
              f"实际 {hash_off}  {'✓' if expect_hash_off == hash_off else '✗'}")

    # 结构一致性：length 是否等于 hash_off + ncs*hs
    expect_len = hash_off + ncs * hs
    print(f"\n  ★ 结构校验: hashOffset + nCodeSlots*hashSize = {expect_len}")
    print(f"              实际 length = {length}   "
          f"{'✓ 吻合' if expect_len == length else '✗ 不吻合，差 %d' % (length - expect_len)}")
    # 特殊槽区起点
    print(f"  ★ 特殊槽区起点 = hashOffset - nSpecialSlots*hashSize = "
          f"{hash_off - nsp * hs}  (应等于 header 长 {hl} 或 ident 段起点 {ident_off})")


for p in sys.argv[1:]:
    parse(p)