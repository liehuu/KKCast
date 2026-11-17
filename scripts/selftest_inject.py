#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证明注入工具的逻辑正确、且错误会被抓到。

注入是这次交付里最危险的一步：改错一个偏移，产物依然能被
zip 打包、依然"看起来正常"，装到设备上才崩。而崩溃现场在别人
的 App 里，日志很难拿。所以宁可在这里用构造样本把边界全测一遍。

做法：用结构已知的合成 Mach-O 当被测样本。
  - 合成样本不是"照抄一份实现"，而是构造真实布局的字节，
    断言注入后的字节满足 Mach-O 规范。这样检查的是真实产出物。
  - 同时用真实的 kkys 二进制做一次端到端（若存在）。

覆盖：
  A. 正常注入：ncmds/sizeofcmds 变化正确、命令可被重新解析
  B. 空隙不足时必须拒绝（不能硬写覆盖 __text）
  C. 空隙非零时必须拒绝（不能覆盖已有数据）
  D. 剥离签名：LC_CODE_SIGNATURE 消失、__LINKEDIT.filesize 收缩
  E. 剥离后 __LINKEDIT 内部指针仍不越界
  F. 幂等性检查用的"已存在"判定能工作
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import inject_dylib as INJ  # noqa: E402

RESULTS = []


def rec(name, ok_, msg):
    RESULTS.append((name, ok_, msg))
    print(f"  {'✅' if ok_ else '❌'} {name}: {msg}")


def p32(v):
    return struct.pack("<I", v)


def p64(v):
    return struct.pack("<Q", v)


def seg_cmd(name, vmaddr, vmsize, fileoff, filesize, nsects, sections):
    """构造 LC_SEGMENT_64。

    segment_command_64 布局（sizeofcmds 从 cmd 字段算起）：
      0  cmd(4)  4 cmdsize(4)  8 segname(16)  24 vmaddr(8)  32 vmsize(8)
      40 fileoff(8)  48 filesize(8)  56 maxprot(4)  60 initprot(4)
      64 nsects(4)  68 flags(4)   → 头共 72 字节
    每个 section_64 是 80 字节。
    """
    cmdsize = 72 + 80 * nsects
    b = p32(INJ.LC_SEGMENT_64) + p32(cmdsize)
    b += name.encode().ljust(16, b"\x00")
    b += p64(vmaddr) + p64(vmsize) + p64(fileoff) + p64(filesize)
    # maxprot, initprot, nsects, flags —— 四个 4 字节，共 16 字节
    b += p32(7) + p32(5) + p32(nsects) + p32(0)
    assert len(b) == 72, f"segment 头应为 72 字节，实际 {len(b)}"
    for sname, addr, size, offset in sections:
        # section_64：sectname(16) segname(16) addr(8) size(8)
        #              offset(4) align(4) reloff(4) nreloc(4) flags(4)
        #              reserved1(4) reserved2(4) reserved3(4) → 80 字节
        b += sname.encode().ljust(16, b"\x00")
        b += name.encode().ljust(16, b"\x00")
        b += p64(addr) + p64(size)
        b += p32(offset) + p32(4) + p32(0) + p32(0)
        b += p32(0x80000400) + p32(0) + p32(0) + p32(0)
    assert len(b) == cmdsize, (len(b), cmdsize)
    return b


def make_sample(gap_byte=0x00, gap_size=0x1000):
    """造一个结构最小但合法的 arm64 Mach-O。

    布局：
      0x0000  header (32)
      0x0020  load commands
      ...     填充（gap_byte）
      0x4000  __text
    """
    text_off = 0x4000
    text_size = 0x100

    cmds = b""
    cmds += seg_cmd("__PAGEZERO", 0, 0x100000000, 0, 0, 0, [])
    cmds += seg_cmd("__TEXT", 0x100000000, 0x4000 + text_size, 0, 0x4000 + text_size, 1,
                    [("__text", 0x100004000, text_size, text_off)])
    cmds += seg_cmd("__LINKEDIT", 0x100010000, 0x1000, 0x5000, 0x1000, 0, [])
    # 正常的 LC_CODE_SIGNATURE，dataoff 指向 __LINKEDIT 内。
    # 真实布局里签名就在 __LINKEDIT 的最末端，所以 dataoff + datasize
    # 要正好等于 __LINKEDIT 的结束位置（0x6000）。
    # 早先把 dataoff 写成 0x5000、datasize 256 而 __LINKEDIT 结束于
    # 0x6000，导致签名后面还有 3840 字节"假数据"，D5 报越界 ——
    # 那是样本不真实，不是工具错。现在样本与真实布局一致。
    cs_off = 0x5F00
    cs_size = 0x100
    cmds += p32(INJ.LC_CODE_SIGNATURE) + p32(16) + p32(cs_off) + p32(cs_size)

    ncmds = 4
    sizeofcmds = len(cmds)

    header = struct.pack("<I", INJ.MH_MAGIC_64)
    header += p32(INJ.CPU_TYPE_ARM64) + p32(0) + p32(2)   # cputype, cpusub, filetype=EXECUTE
    header += p32(ncmds) + p32(sizeofcmds) + p32(0) + p32(0)
    assert len(header) == 32

    total = 0x6000
    buf = bytearray(total)
    buf[0:32] = header
    buf[32:32 + len(cmds)] = cmds
    cmds_end = 32 + len(cmds)
    # 填充区
    for i in range(cmds_end, text_off):
        buf[i] = gap_byte
    # __text 里放点可识别的字节，用来验证"没被覆盖"
    for i in range(text_off, text_off + text_size):
        buf[i] = 0xAA
    # 签名区
    for i in range(0x5F00, 0x6000):
        buf[i] = 0xCC
    return bytes(buf), cmds_end, text_off


def test_A_normal():
    print("\nA. 正常注入")
    data, cmds_end, text_off = make_sample()
    m = INJ.MachO(data)
    out = INJ.inject_inplace(m, "@executable_path/Frameworks/KKCast.dylib")

    # 重新解析，确认结构可读
    m2 = INJ.MachO(bytes(out))
    if m2.ncmds != m.ncmds + 1:
        rec("A1 ncmds+1", False, f"{m.ncmds} → {m2.ncmds}")
        return
    rec("A1 ncmds+1", True, f"{m.ncmds} → {m2.ncmds}")

    if m2.sizeofcmds <= m.sizeofcmds:
        rec("A2 sizeofcmds 增大", False, f"{m.sizeofcmds} → {m2.sizeofcmds}")
    else:
        rec("A2 sizeofcmds 增大", True, f"0x{m.sizeofcmds:x} → 0x{m2.sizeofcmds:x}")

    # 命令链必须自洽
    off = 32
    found = False
    for _ in range(m2.ncmds):
        cmd = INJ.u32(m2.data, off)
        cs = INJ.u32(m2.data, off + 4)
        if cmd == INJ.LC_LOAD_DYLIB:
            noff = INJ.u32(m2.data, off + 8)
            nm = bytes(m2.data[off + noff:off + cs]).split(b"\x00")[0].decode()
            if nm == "@executable_path/Frameworks/KKCast.dylib":
                found = True
        off += cs
    if off != 32 + m2.sizeofcmds:
        rec("A3 命令链自洽", False, f"结束于 {off}，应为 {32+m2.sizeofcmds}")
    else:
        rec("A3 命令链自洽", True, f"结束于 {off}")
    rec("A4 新命令可解析", found, "找到 KKCast.dylib 的 LC_LOAD_DYLIB")

    # __text 没被碰
    text_ok = all(b == 0xAA for b in out[text_off:text_off + 0x100])
    rec("A5 __text 未被覆盖", text_ok, "原有代码字节完好")

    # 文件长度不变（策略 A 不移动数据）
    rec("A6 文件长度不变", len(out) == len(data), f"{len(data)} → {len(out)}")


def test_B_no_space():
    print("\nB. 空隙不足必须拒绝")
    # 造一个 cmds_end 紧贴 __text 的样本：gap 只有 8 字节
    text_off = 0x4000
    cmds = seg_cmd("__TEXT", 0x100000000, text_off + 0x100, 0, text_off + 0x100, 1,
                   [("__text", 0x100004000, 0x100, text_off)])
    # 用一堆 LC_UUID 把空间塞满
    uuid_cmd = p32(0x1B) + p32(24) + b"\x11" * 16
    fill = b""
    while 32 + len(cmds) + len(fill) + 24 < text_off - 8:
        fill += uuid_cmd
    cmds += fill
    ncmds = 1 + len(fill) // 24
    header = struct.pack("<I", INJ.MH_MAGIC_64) + p32(INJ.CPU_TYPE_ARM64) + p32(0) + p32(2)
    header += p32(ncmds) + p32(len(cmds)) + p32(0) + p32(0)
    buf = bytearray(text_off + 0x100)
    buf[0:32] = header
    buf[32:32 + len(cmds)] = cmds

    m = INJ.MachO(bytes(buf))
    avail, _ = m.slack()
    try:
        INJ.inject_inplace(m, "@executable_path/Frameworks/KKCast.dylib")
        rec("B1 空隙不足时拒绝", False, f"空隙 {avail} 字节却注入成功了（应当抛错）")
    except SystemExit as e:
        msg = str(e)
        rec("B1 空隙不足时拒绝", "空隙不足" in msg, f"正确抛错：{msg[:50]}")


def test_C_nonzero_gap():
    print("\nC. 空隙非零必须拒绝")
    data, cmds_end, text_off = make_sample(gap_byte=0x5A)
    m = INJ.MachO(data)
    try:
        INJ.inject_inplace(m, "@executable_path/Frameworks/KKCast.dylib")
        rec("C1 非零填充时拒绝", False, "填充区不是零却注入成功（会破坏数据）")
    except SystemExit as e:
        rec("C1 非零填充时拒绝", "全零" in str(e), f"正确抛错：{str(e)[:60]}")


def test_D_strip():
    print("\nD. 剥离签名")
    data, cmds_end, text_off = make_sample()
    m = INJ.MachO(data)
    out = INJ.inject_inplace(m, "@executable_path/Frameworks/KKCast.dylib")
    m2 = INJ.MachO(bytes(out))
    out2, removed = INJ.strip_codesig(m2)

    if removed <= 0:
        rec("D1 移除了签名命令", False, f"removed={removed}")
        return
    rec("D1 移除了签名命令", True, f"移除 {removed} 字节")

    m3 = INJ.MachO(bytes(out2))
    off = 32
    has_cs = False
    for _ in range(m3.ncmds):
        cmd = INJ.u32(m3.data, off)
        cs = INJ.u32(m3.data, off + 4)
        if cmd == INJ.LC_CODE_SIGNATURE:
            has_cs = True
        off += cs
    rec("D2 LC_CODE_SIGNATURE 已消失", not has_cs, "重新解析确认无该命令")
    rec("D3 命令链仍自洽", off == 32 + m3.sizeofcmds, f"结束于 {off}")

    # 文件应被截断到 dataoff
    rec("D4 文件被截断", len(out2) < len(out), f"{len(out)} → {len(out2)}")

    # D5：__LINKEDIT 必须不越界。
    #
    # 注意判据：删掉 LC_CODE_SIGNATURE 这条 16 字节的命令后，文件本身
    # 就会短 16 字节——那是"少了一条命令"，不是"截断数据"。
    # 早先把"文件长度变短"当成失败，是判据错了：它把合法行为
    # 判成缺陷，属于假 FAIL。真正要保证的是**段声明不越过文件末尾**。
    le = m3.linkedit_seg()
    end = le["fileoff"] + le["filesize"]
    rec("D5 __LINKEDIT 不越界", end <= len(out2), f"声明结束 {end} <= 文件 {len(out2)}")

    # D6：真实布局下（签名在末端）应该真的截断掉签名数据，
    #     否则新包里还留着一份无用的旧签名 blob。
    rec("D6 尾部签名被截掉", len(out2) < len(data),
        f"{len(data)} → {len(out2)}（少了签名与命令）")


def test_E_idempotent():
    print("\nE. 已注入检测")
    data, _, _ = make_sample()
    m = INJ.MachO(data)
    out = INJ.inject_inplace(m, "@executable_path/Frameworks/KKCast.dylib")

    # 模拟 build_ipa.py 的"已存在"判定
    m2 = INJ.MachO(bytes(out))
    off = m2.header_size
    already = False
    for _ in range(m2.ncmds):
        cmd = INJ.u32(m2.data, off)
        cs = INJ.u32(m2.data, off + 4)
        if cmd == INJ.LC_LOAD_DYLIB:
            noff = INJ.u32(m2.data, off + 8)
            nm = bytes(m2.data[off + noff:off + cs]).split(b"\x00")[0].decode("utf-8", "replace")
            if "KKCast.dylib" in nm:
                already = True
        off += cs
    rec("E1 二次注入能被识别", already, "重复跑不会插第二条")


def test_F_real_binary():
    print("\nF. 真实二进制端到端（若存在）")
    cands = [
        os.path.join(HERE, "..", "..", "kkys_work", "movie.orig"),
        "/tmp/movie.orig",
    ]
    real = None
    for c in cands:
        c = os.path.abspath(c)
        if os.path.isfile(c):
            real = c
            break
    if not real:
        print("  ⚠️  没有真实样本，跳过（CI 上不需要，本地验证用）")
        return

    with open(real, "rb") as f:
        raw = f.read()
    m = INJ.MachO(raw)
    out = INJ.inject_inplace(m, "@executable_path/Frameworks/KKCast.dylib")
    m2 = INJ.MachO(bytes(out))
    out2, _ = INJ.strip_codesig(m2)
    m3 = INJ.MachO(bytes(out2))

    off = 32
    ok_chain = True
    found = False
    for _ in range(m3.ncmds):
        if off + 8 > len(out2):
            ok_chain = False
            break
        cmd = INJ.u32(m3.data, off)
        cs = INJ.u32(m3.data, off + 4)
        if cs < 8:
            ok_chain = False
            break
        if cmd == INJ.LC_LOAD_DYLIB:
            noff = INJ.u32(m3.data, off + 8)
            nm = bytes(m3.data[off + noff:off + cs]).split(b"\x00")[0].decode("utf-8", "replace")
            if "KKCast.dylib" in nm:
                found = True
        off += cs

    rec("F1 真实二进制命令链完整", ok_chain and off == 32 + m3.sizeofcmds, f"结束于 {off}")
    rec("F2 真实二进制注入成功", found, "找到 LC_LOAD_DYLIB")

    # 所有段的 end 都不能超过文件长度
    bad = []
    for s in m3.segments:
        if s["fileoff"] + s["filesize"] > len(out2):
            bad.append(s["name"])
    rec("F3 所有段不越界", not bad, f"越界段：{bad}" if bad else "全部在文件内")


def main():
    print("=" * 66)
    print("注入工具自检")
    print("=" * 66)
    test_A_normal()
    test_B_no_space()
    test_C_nonzero_gap()
    test_D_strip()
    test_E_idempotent()
    test_F_real_binary()

    print()
    print("=" * 66)
    bad = [r for r in RESULTS if not r[1]]
    for name, ok_, msg in RESULTS:
        print(f"  {'✅' if ok_ else '❌'} {name:28s} {msg}")
    print("=" * 66)
    if bad:
        print(f"结论：FAIL（{len(bad)}/{len(RESULTS)} 项未通过）")
        return 1
    print(f"结论：PASS（{len(RESULTS)} 项全部通过）")
    return 0


if __name__ == "__main__":
    sys.exit(main())