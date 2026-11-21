#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主程序注入前后字节级差异：按"数据区"而不是"文件偏移"对齐比较。

为什么必须这样做：
  插入 load command 会让后续所有字节位移，直接逐偏移对比会全红，
  得到"到处都是差异"的假结论。正确做法是先按 load command 链与
  各段 fileoff 建立"逻辑区"映射，再逐区比较内容。

判据：除了 (a) load command 区 (b) __LINKEDIT 尾部的签名区，
其余每个段的内容必须逐字节相同。任何代码段/数据段内容差异 = 注入破坏了二进制。
"""
import hashlib
import struct
import sys

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def parse(path):
    data = open(path, "rb").read()
    assert u32(data, 0) == 0xFEEDFACF, path
    ncmds, sizeofcmds = u32(data, 16), u32(data, 20)
    off = 32
    segs = []
    codesig = None
    lc_cmds = []
    for _ in range(ncmds):
        cmd, cs = u32(data, off), u32(data, off + 4)
        if cmd == LC_SEGMENT_64:
            name = bytes(data[off + 8:off + 24]).split(b"\x00")[0].decode("ascii", "replace")
            fo, fs = u64(data, off + 40), u64(data, off + 48)
            segs.append((name, fo, fs))
        elif cmd == LC_CODE_SIGNATURE:
            codesig = (u32(data, off + 8), u32(data, off + 12))
        lc_cmds.append((off, cmd, cs))
        off += cs
    return dict(data=data, size=len(data), ncmds=ncmds, sizeofcmds=sizeofcmds,
                segs=segs, codesig=codesig, lc_end=32 + sizeofcmds, lcs=lc_cmds)


def digest(b):
    return hashlib.sha256(b).hexdigest()[:16]


def compare(pa, pb):
    A, B = parse(pa), parse(pb)
    print(f"\n=== 差异分析 ===")
    print(f"A = {pa}\n    size={A['size']} ncmds={A['ncmds']} sizeofcmds={A['sizeofcmds']} "
          f"lc_end={A['lc_end']} codesig={A['codesig']}")
    print(f"B = {pb}\n    size={B['size']} ncmds={B['ncmds']} sizeofcmds={B['sizeofcmds']} "
          f"lc_end={B['lc_end']} codesig={B['codesig']}")

    # 计算 CODE_SIGNATURE 之前内容（payload）的边界
    a_pay_end = A["codesig"][0] if A["codesig"] else A["size"]
    b_pay_end = B["codesig"][0] if B["codesig"] else B["size"]
    print(f"\n  payload 区（签名区之前）: A=0..{a_pay_end}  B=0..{b_pay_end}  "
          f"长度差={b_pay_end - a_pay_end}")
    print(f"  签名区: A={A['codesig']}  B={B['codesig']}")

    sa = dict((n, (fo, fs)) for n, fo, fs in A["segs"])
    sb = dict((n, (fo, fs)) for n, fo, fs in B["segs"])
    print(f"\n  --- 按段比较内容 ---")
    common = [n for n in sa if n in sb]
    # 只比 __TEXT(含 cmds/代码) / __DATA_CONST / __DATA / __LINKEDIT
    for name in ["__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"]:
        if name not in sa or name not in sb:
            print(f"  {name:<14} 缺失")
            continue
        (afo, afs), (bfo, bfs) = sa[name], sb[name]
        # __TEXT 含 load command，必然不同；比它的"cmds 之后"部分
        if name == "__TEXT":
            a_start = max(A["lc_end"], afo) if afo == 0 else afo + A["lc_end"]
            b_start = max(B["lc_end"], bfo) if bfo == 0 else bfo + B["lc_end"]
            # __TEXT fileoff=0，从 lc_end 之后开始比
            a_chunk = A["data"][A["lc_end"]:afo + afs]
            b_chunk = B["data"][B["lc_end"]:bfo + bfs]
            # 两个 chunk 长度必然差 sizeofcmds 差
            dlen = len(b_chunk) - len(a_chunk)
            print(f"  {name:<14} A[{A['lc_end']}..{afo+afs}] len={len(a_chunk)}  "
                  f"B[{B['lc_end']}..{bfo+bfs}] len={len(b_chunk)}  长度差={dlen}")
            if dlen == 0:
                same = A["data"][A["lc_end"]:afo + afs] == B["data"][B["lc_end"]:bfo + bfs]
                print(f"      内容{'相同' if same else '✗ 不同'}  sha A={digest(a_chunk)} B={digest(b_chunk)}")
            else:
                # 位移不同，需要按"去掉插入的 16 字节 LC_CODE_SIGNATURE"对齐比
                print(f"      ⚠ 长度不同，无法直接比；插入的 cmds 导致位移 {dlen} 字节")
                # 逐页比较 __text 内容：以 pagesize 16KB 对齐后的偏移比较
                # A 的页 1..N vs B 的页 1..N，但要考虑 B 多出的 16 字节
                print(f"      → 见下方 page 级对齐比较")
        else:
            a_chunk = A["data"][afo:afo + afs]
            b_chunk = B["data"][bfo:bfo + bfs]
            eq = a_chunk == b_chunk
            print(f"  {name:<14} A[{afo}..{afo+afs}] len={len(a_chunk)}  "
                  f"B[{bfo}..{bfo+bfs}] len={len(b_chunk)}  "
                  f"{'✓ 内容相同' if eq else '✗ 内容不同'}")
            if not eq and len(a_chunk) == len(b_chunk):
                diffs = [i for i in range(len(a_chunk)) if a_chunk[i] != b_chunk[i]]
                print(f"      差异 {len(diffs)} 字节，首 10 个相对偏移: {diffs[:10]}"
                      f"  → 绝对 A={afo+diffs[0]} B={bfo+diffs[0]}")
                for d in diffs[:8]:
                    print(f"        @+{d}: A={a_chunk[d-d if d<8 else d-8:d+8].hex()} "
                          f"B={b_chunk[d-8:d+8].hex()}")

    # __TEXT 内容用"页对齐 + 尾部对齐"双策略确认
    print(f"\n  --- __TEXT 正文（跳过 load command 区）尾部对齐比较 ---")
    (afo, afs) = sa["__TEXT"]; (bfo, bfs) = sb["__TEXT"]
    # 取 __TEXT 最后一个 16384 页之前的固定长度做比较：从末尾往前取 1MB
    N = min(afs - A["lc_end"], bfs - B["lc_end"], 1 << 20)
    a_tail = A["data"][afo + afs - N: afo + afs]
    b_tail = B["data"][bfo + bfs - N: bfo + bfs]
    print(f"      尾部 {N} 字节: {'✓ 相同' if a_tail == b_tail else '✗ 不同'}  "
          f"sha A={digest(a_tail)} B={digest(b_tail)}")
    # 头部（cmds 之后到第一页末）
    first_page_end = 16384
    a_head = A["data"][A["lc_end"]:first_page_end]
    b_head = B["data"][B["lc_end"]:first_page_end]
    print(f"      第0页 cmds之后..16384: A len={len(a_head)} B len={len(b_head)} "
          f"{'✓ 相同' if a_head == b_head else '需按尾部对齐'}")
    if a_head != b_head and len(a_head) != len(b_head):
        # 从页尾倒着比
        m = min(len(a_head), len(b_head))
        print(f"      尾部对齐 {m} 字节: "
              f"{'✓ 相同' if a_head[-m:] == b_head[-m:] else '✗ 不同'}")


compare(sys.argv[1], sys.argv[2])