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

    # ★ strip_codesig 是原地修改：它会左移 cmds 区、改 ncmds/sizeofcmds，
    #   最后还 macho.data = macho.data[:dataoff] 把文件截短。
    #   所以"剥离前"的所有基准必须在这一行之前快照下来。
    #   教训：先前直接拿 m2.data / m2.sizeofcmds / m2.segments 当基准，
    #   等于拿剥离后的结果跟它自己比 —— D6 恒红（长度永远相等）、
    #   D4b 恒绿（两边是同一份数据），一个假 FAIL 加一个假 PASS。
    pre_strip = bytes(m2.data)
    pre_sizeofcmds = m2.sizeofcmds
    pre_segments = {s["name"]: (s["fileoff"], s["filesize"]) for s in m2.segments}

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

    # ★ D4（判据已按 2026-11-21 的真机闪退缺陷反转）
    #
    # 旧判据是"len(out2) < len(out) 即通过"。这条判据本身把缺陷判成了
    # 合法行为：v1 用 `del data[off:off+16]` 从文件中间抠掉命令，
    # 文件确实变短了，断言变绿 —— 但那段代码把其后**所有字节前移 16**，
    # 而段的 fileoff 与各 dataoff 全都没改。真机 100% 启动即闪退。
    #
    # 正确的判据是：删命令只能发生在 load command 区内（左移 + 零填充），
    # 文件长度不变；之后截掉尾部旧签名是另一件事，只能发生在文件末尾。
    lc_end_before = 32 + pre_sizeofcmds
    lc_end_after = 32 + m3.sizeofcmds
    rec("D4a cmds 区收缩了 16 字节",
        lc_end_after == lc_end_before - removed,
        f"lc_end {lc_end_before} → {lc_end_after}（removed={removed}）")

    # D4b：cmds 区之外、被截断区之前的字节必须原样不动。
    #
    # 三个坑，逐个踩过：
    #  1. 不能写成 len(out2) == len(pre_strip)：strip_codesig 同时做两件事
    #     ——删命令（不改长度）+ 截尾部旧签名（缩短），混比长度必假 FAIL。
    #  2. 基准必须用 pre_strip 快照。strip_codesig 原地改写 m2.data，
    #     拿 m2.data 比就是自己跟自己比 → 假 PASS。
    #  3. 比对起点必须是 lc_end_before（原 cmds 区结束处），不能是
    #     lc_end_after。因为 [lc_end_after, lc_end_before) 这 16 字节
    #     正是删掉那条命令腾出来的位置，按设计就被零填充了，
    #     把它算进"未移动"区间必然假 FAIL。
    tail_start = lc_end_before
    strip_at = min(len(out2), len(pre_strip))
    mid_before = pre_strip[tail_start:strip_at]
    mid_after = bytes(out2[tail_start:strip_at])
    rec("D4b cmds 区之后的数据未被移动",
        mid_before == mid_after,
        f"比对 [{tail_start}, {strip_at}) 共 {strip_at - tail_start} 字节"
        + ("" if mid_before == mid_after else " —— 有字节变了"))

    # D4b2：腾出来的区间必须是零，不是残留旧命令 —— 证明实现是
    #       "左移 + 尾部补零"，而不是"留个洞"或"复制别的字节过来"。
    freed = bytes(out2[lc_end_after:lc_end_before])
    rec("D4b2 腾出的 cmds 区已清零", set(freed) <= {0},
        f"[{lc_end_after}, {lc_end_before}) 共 {len(freed)} 字节，"
        f"非零 {sum(1 for b in freed if b)} 个")

    # D4c：所有段 fileoff 未变
    seg_before = pre_segments
    seg_after = {s["name"]: (s["fileoff"], s["filesize"]) for s in m3.segments}
    moved = [n for n in seg_after
             if n in seg_before and seg_after[n][0] != seg_before[n][0]]
    rec("D4c 所有段 fileoff 未变", not moved, f"发生位移的段: {moved}")

    # D4d：真正的内容锚点 —— 段内数据必须还在声明的位置。
    #
    # 两个必须避开的坑：
    #  1. fileoff=0 的段（__TEXT），其头部**就是** load command 区，
    #     删命令后必然变化。必须从 lc_end_before 之后开始比。
    #  2. 被截断的尾部区（旧签名）也不比。
    anchor_ok = True
    anchor_msg = []
    for name, (fo, fs) in pre_segments.items():
        if fs == 0:
            continue
        start = max(fo, lc_end_before)         # 跳过 cmds 区
        end = min(fo + fs, strip_at)           # 跳过被截断的尾部
        n = min(end - start, 4096)
        if n <= 0:
            continue
        # 左边用快照，右边用产物 —— 两侧来源不同，这条检查才可能失败
        if pre_strip[start:start + n] != bytes(out2[start:start + n]):
            anchor_ok = False
            d = next(i for i in range(n)
                     if pre_strip[start + i] != out2[start + i])
            anchor_msg.append(f"{name}@+{d}")
    rec("D4d 段内容仍在声明偏移处", anchor_ok,
        f"漂移: {anchor_msg}" if anchor_msg else
        f"{len(pre_segments)} 个段全部锚点命中")

    # D5：__LINKEDIT 必须不越界。
    #
    # 注意判据：删掉 LC_CODE_SIGNATURE 这条 16 字节的命令后，文件本身
    # 就会短 16 字节——那是"少了一条命令"，不是"截断数据"。
    # 早先把"文件长度变短"当成失败，是判据错了：它把合法行为
    # 判成缺陷，属于假 FAIL。真正要保证的是**段声明不越过文件末尾**。
    le = m3.linkedit_seg()
    end = le["fileoff"] + le["filesize"]
    rec("D5 __LINKEDIT 不越界", end <= len(out2), f"声明结束 {end} <= 文件 {len(out2)}")

    # D6：尾部旧签名 blob 必须被截掉（它已无意义，留着会占 41KB）
    # 基准必须是 pre_strip（剥离前的快照）。用 m2.data 是错的 ——
    # strip_codesig 已经把 m2.data 截短了，两边恒等，断言永远红。
    rec("D6 尾部签名被截掉", len(out2) < len(pre_strip),
        f"{len(pre_strip)} → {len(out2)}"
        + (f"（少 {len(pre_strip) - len(out2)} 字节）" if len(out2) < len(pre_strip)
           else " —— 没有变短，旧签名 blob 还在"))

    # D7：__LINKEDIT 的 filesize 必须收窄到 "文件末尾 - fileoff"，
    #     否则 dyld 认为该段头有 41KB 数据而文件里没有，读到 EOF 外。
    le_end = m3.linkedit_seg()["fileoff"] + m3.linkedit_seg()["filesize"]
    rec("D7 __LINKEDIT 恰好收到文件末尾", le_end == len(out2),
        f"声明结束 {le_end} == 文件 {len(out2)}")


def test_D0_replay_v1_shift_defect():
    """回放 v1 的 `del data[off:off+16]` 位移缺陷，证明 D4 系列真的会红。

    ★ 没有这一段，D4b/D4c/D4d 就只是"看起来在检查"。
      回放样本必须**完整复刻 v1 的错误实现**，只留这一个缺陷：
        1. 从 cmds 区中间 del 掉 16 字节（其后所有字节前移 16）
        2. ncmds / sizeofcmds 照常减 —— 命令链在逻辑上仍然自洽
        3. 不碰任何 fileoff / dataoff
      这样 D3（命令链自洽）会绿，而 D4b/D4c/D4d 必须红。
      如果全绿，说明判据根本没测到位移。
    """
    print("\nD0. 回放 v1 位移缺陷（证明 D4 系列能失败）")
    data, _, _ = make_sample()
    m = INJ.MachO(data)
    out = INJ.inject_inplace(m, "@executable_path/Frameworks/KKCast.dylib")

    m2 = INJ.MachO(bytes(out))
    lc_end = 32 + m2.sizeofcmds
    pre = bytes(m2.data)
    pre_segments = {s["name"]: (s["fileoff"], s["filesize"]) for s in m2.segments}

    # v1 原样实现：命中即 del，不做任何左移/补零
    hits = m2.find_cmd_offsets(INJ.LC_CODE_SIGNATURE)
    assert hits, "样本里没有 LC_CODE_SIGNATURE，回放无效"
    buggy = bytearray(pre)
    removed = 0
    for off, cmdsize in sorted(hits, reverse=True):
        del buggy[off:off + cmdsize]          # ← 就是这一行毁了文件
        removed += cmdsize
    buggy[16:20] = p32(INJ.u32(bytes(buggy), 16) - len(hits))
    buggy[20:24] = p32(INJ.u32(bytes(buggy), 20) - removed)
    buggy = bytes(buggy)

    def refs(buf):
        """收集所有 dataoff 型引用的实际内容，用来判定位移。"""
        mm = INJ.MachO(bytes(buf))
        res = {}
        off = mm.header_size
        for _ in range(mm.ncmds):
            cmd = INJ.u32(mm.data, off)
            cs = INJ.u32(mm.data, off + 4)
            # LC_SEGMENT_64 的 fileoff/filesize 单独看，不在此列
            if cmd in (0x80000034,          # LC_DYLD_CHAINED_FIXUPS
                       0x80000022,          # LC_DYLD_EXPORTS_TRIE
                       0x80000033,          # LC_DYLD_INFO / DYLD_INFO_ONLY
                       0x26,                # LC_FUNCTION_STARTS
                       0x29,                # LC_DATA_IN_CODE
                       0x2,                 # LC_SYMTAB
                       0x1D):               # LC_CODE_SIGNATURE
                doff = INJ.u32(mm.data, off + 8)
                dsz = INJ.u32(mm.data, off + 12)
                if dsz and doff + dsz <= len(mm.data):
                    res[cmd] = bytes(mm.data[doff:doff + dsz])
            off += cs
        return res, mm

    refs_pre, _ = refs(pre)
    refs_bug, mm_bug = refs(buggy)

    # R1：命令链依然自洽 —— 证明回放样本"只坏了位移这一件事"
    o = 32
    ok_chain = True
    try:
        for _ in range(mm_bug.ncmds):
            cs = INJ.u32(mm_bug.data, o + 4)
            if cs == 0 or o + cs > 32 + mm_bug.sizeofcmds:
                ok_chain = False
                break
            o += cs
    except Exception:
        ok_chain = False
    rec("R1 回放样本命令链仍自洽", ok_chain and o == 32 + mm_bug.sizeofcmds,
        f"结束于 {o}（对照 D3 也会绿，说明缺陷只在数据位置）")

    # R2：段 fileoff 一字未改 —— 正是缺陷的特征：表没动，数据动了
    seg_bug = {s["name"]: (s["fileoff"], s["filesize"]) for s in mm_bug.segments}
    rec("R2 回放样本的段 fileoff 未改", seg_bug == pre_segments,
        "声明偏移原样保留（缺陷才成立）")

    # R3：dataoff 引用读到的内容必须已经变了 —— 这就是 dyld 看到的东西。
    #
    # ★ 合成样本里除了签名命令没有别的 dataoff 引用，这一段在合成样本上
    #   永远拿不到可比的引用集。所以：合成样本有引用就断言，没有就跳过，
    #   真正的位移证据交给 F4（真实二进制上的 chained fixups 比对）。
    lc_end_bug = 32 + mm_bug.sizeofcmds
    comparable = [c for c in refs_pre if c != 0x1D]
    if not comparable:
        print("  ⏭️  R3 合成样本无 dataoff 引用，改由 F4 在真实二进制上验证")
    else:
        broken = []
        for cmd in comparable:
            blob = refs_pre[cmd]
            if cmd not in refs_bug:
                broken.append(f"0x{cmd:x}<丢失>")
            elif refs_bug[cmd] != blob:
                d = next((i for i in range(min(len(blob), len(refs_bug[cmd])))
                          if blob[i] != refs_bug[cmd][i]), 0)
                broken.append(f"0x{cmd:x}@+{d}")
        rec("R3 回放样本的 dataoff 引用已错位", bool(broken),
            f"错位: {broken}" if broken else "引用内容没变，回放无效（判据需重写）")

    # R4：用 D4b 的判据去判回放样本，必须红
    strip_at = min(len(buggy), len(pre))
    mid_same = pre[lc_end:strip_at] == buggy[lc_end:strip_at]
    rec("R4 D4b 判据在缺陷样本上必然失败", not mid_same,
        "判据成功捕获位移" if not mid_same else
        "❌ 判据在缺陷样本上也通过了 —— 它是装饰")

    # R5：用 D4d 的判据去判回放样本，必须红
    drifted = []
    for name, (fo, fs) in pre_segments.items():
        if fs == 0:
            continue
        s0 = max(fo, lc_end)
        e0 = min(fo + fs, strip_at)
        n = min(e0 - s0, 4096)
        if n > 0 and pre[s0:s0 + n] != buggy[s0:s0 + n]:
            drifted.append(name)
    rec("R5 D4d 判据在缺陷样本上必然失败", bool(drifted),
        f"检出漂移段: {drifted}" if drifted else "❌ 判据在缺陷样本上没检出漂移")

    # R6：缺陷样本的文件长度比产物短 —— 但这恰恰是"看起来更小更合理"，
    #     所以绝不能拿长度当通过条件（旧 D4 就是这么错的）
    rec("R6 长度变短不能作为正确性证据", len(buggy) < len(pre),
        f"缺陷产物 {len(buggy)} < {len(pre)} —— 长度判据会把缺陷判成 PASS，"
        f"这正是旧 D4 的错误")


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

    # ── F4/F5/F6：位移不变性在真实二进制上的硬证据 ──────────────────
    #
    # 这是整个排查的现场：v1 用 del 从中间抠掉 16 字节后，
    # LC_DYLD_CHAINED_FIXUPS.dataoff 仍写 10780672，dyld 在错位处
    # 读到 (3249,1,0,0,5,0,0)，imports_format=0 非法 → 绑定阶段 abort
    # → 看到启动画面即闪退。
    # 所以必须逐字节比对"注入+剥离后的产物"与"原始输入"的引用内容。

    def fixed_refs(buf):
        """返回 {cmd: (dataoff, 内容)}，只收 dataoff 型引用。"""
        mm = INJ.MachO(bytes(buf))
        res = {}
        off = mm.header_size
        for _ in range(mm.ncmds):
            cmd = INJ.u32(mm.data, off)
            cs = INJ.u32(mm.data, off + 4)
            if cmd in (0x80000034, 0x80000022, 0x80000033, 0x26, 0x29, 0x2, 0x1D):
                doff = INJ.u32(mm.data, off + 8)
                dsz = INJ.u32(mm.data, off + 12)
                if dsz and doff + dsz <= len(mm.data):
                    res[cmd] = (doff, bytes(mm.data[doff:doff + dsz]))
            off += cs
        return res

    refs_orig = fixed_refs(raw)
    refs_new = fixed_refs(out2)
    drift = []
    for cmd, (doff0, blob0) in refs_orig.items():
        if cmd == 0x1D:                        # 旧签名已按设计删除
            continue
        if cmd not in refs_new:
            drift.append(f"0x{cmd:x} 丢失")
            continue
        doff1, blob1 = refs_new[cmd]
        if doff0 != doff1:
            drift.append(f"0x{cmd:x} dataoff 0x{doff0:x}→0x{doff1:x}")
        elif blob0 != blob1:
            d = next((i for i in range(min(len(blob0), len(blob1)))
                      if blob0[i] != blob1[i]), 0)
            drift.append(f"0x{cmd:x} 内容在 +{d} 处变化")
    rec("F4 真实二进制所有 dataoff 引用未位移", not drift,
        f"{len(refs_orig) - 1} 条引用逐字节比对，偏移: {drift}" if drift
        else f"{len(refs_orig) - 1} 条引用逐字节一致（含 CHAINED_FIXUPS）")

    # F5：chained fixups header 必须仍然可解析且合法。
    #     这是 dyld 加载时第一个读的结构，它的七个字段任何一个非法
    #     都会在绑定前 abort，且崩溃现场看起来和签名问题一模一样。
    fx = refs_new.get(0x80000034)
    if fx is None:
        rec("F5 chained fixups header 可解析", False, "产物里没有 CHAINED_FIXUPS")
    else:
        doff, blob = fx
        f = struct.unpack("<7I", blob[:28])
        ver, st_off, imp_off, sym_off, imp_cnt, imp_fmt, sym_fmt = f
        ok_ = (ver == 0 and imp_fmt in (1, 2, 3) and sym_fmt in (0, 1)
               and st_off < len(blob) and imp_off < len(blob)
               and sym_off <= len(blob))
        rec("F5 chained fixups header 可解析", ok_,
            f"@0x{doff:x} fixups_version={ver} starts={st_off} imports={imp_off} "
            f"symbols={sym_off} imports_count={imp_cnt} imports_format={imp_fmt} "
            f"symbols_format={sym_fmt}")

        # F6：imports_format=1 的位域解出来必须全部落在依赖库范围内。
        #     位移后 imp_fmt 会变成 32/0 之类，这条直接红。
        #
        # ★ 判据上界不能硬编码，也不能只数 LC_LOAD_DYLIB(0xC)。
        #   实测 movie.orig：42 条 LC_LOAD_DYLIB + 13 条
        #   0x80000018（LC_LOAD_WEAK_DYLIB | LC_REQ_DYLD）= 55 个 ordinal 槽位，
        #   而导入表里出现的最大 ordinal 正是 55。
        #   我最初把上界写成 40，报出 438 条"越界"——全是假 FAIL，
        #   根因是漏数了带 LC_REQ_DYLD(0x80000000) 位的 dylib 变体。
        if imp_fmt == 1:
            # dyld 的 ordinal 按所有 dylib 类命令的出现顺序编号，
            # LC_REQ_DYLD 位不影响它是否占槽位。
            dylib_cmds = {0x0C, 0x0D, 0x18, 0x1F, 0x20, 0x24}
            n_slots = 0
            o = m3.header_size
            for _ in range(m3.ncmds):
                c = INJ.u32(out2, o) & 0x7FFFFFFF   # 抹掉 LC_REQ_DYLD
                if c in dylib_cmds:
                    n_slots += 1
                o += INJ.u32(out2, o + 4)

            badimp = []
            base = doff + imp_off
            for i in range(min(imp_cnt, 5000)):
                off_i = base + i * 4
                if off_i + 4 > len(out2):
                    badimp.append(f"#{i} 越界")
                    break
                v = INJ.u32(out2, off_i)
                lib = v & 0xFF
                name_off = v >> 9
                if lib not in (0, 0xFD, 0xFE, 0xFF) and not (1 <= lib <= n_slots):
                    badimp.append(f"#{i} lib_ordinal={lib} > {n_slots}")
                if name_off >= len(blob):
                    badimp.append(f"#{i} name_offset={name_off} 越出符号池")
                if len(badimp) > 5:
                    break
            rec("F6 chained fixups 导入表可逐条解析", not badimp,
                f"{imp_cnt} 条导入合法，ordinal 上界 {n_slots}（含弱链接槽位）"
                if not badimp else f"异常: {badimp}")
        else:
            print(f"  ⏭️  F6 imports_format={imp_fmt}（非 1），跳过位域解析")


def main():
    print("=" * 66)
    print("注入工具自检")
    print("=" * 66)
    test_A_normal()
    test_B_no_space()
    test_C_nonzero_gap()
    test_D_strip()
    test_D0_replay_v1_shift_defect()
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