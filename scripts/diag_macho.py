#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mach-O 结构诊断：段/节 fileoff 与 load command 链的物理一致性。

判据来源：不是"我的签名能自验通过"，而是"文件布局对一个真实 dyld 是否成立"。
重点看 load command 插入是否把后续数据整体位移，而 fileoff 没有同步。
"""
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_CODE_SIGNATURE = 0x1D
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_DYLD_EXPORTS_TRIE = 0x80000033

LINKED_IT_LC = {
    LC_SYMTAB: "LC_SYMTAB",
    LC_DYSYMTAB: "LC_DYSYMTAB",
    LC_CODE_SIGNATURE: "LC_CODE_SIGNATURE",
    LC_DYLD_INFO: "LC_DYLD_INFO",
    LC_DYLD_INFO_ONLY: "LC_DYLD_INFO_ONLY",
    LC_DYLD_CHAINED_FIXUPS: "LC_DYLD_CHAINED_FIXUPS",
    LC_FUNCTION_STARTS: "LC_FUNCTION_STARTS",
    LC_DATA_IN_CODE: "LC_DATA_IN_CODE",
    LC_DYLD_EXPORTS_TRIE: "LC_DYLD_EXPORTS_TRIE",
}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def analyse(path):
    data = open(path, "rb").read()
    magic = u32(data, 0)
    print(f"\n=== {path} ===")
    print(f"filesize={len(data)} magic=0x{magic:08x} "
          f"ncmds={u32(data,16)} sizeofcmds={u32(data,20)}")
    if magic != MH_MAGIC_64:
        print("  !! 不是 MH_MAGIC_64")
        return

    ncmds = u32(data, 16)
    sizeofcmds = u32(data, 20)
    off = 32
    segs = []
    lcs = []
    for i in range(ncmds):
        cmd = u32(data, off)
        cs = u32(data, off + 4)
        if cs < 8:
            print(f"  !! cmdsize 非法 {cs} @ lc[{i}] off={off}")
            return
        if cmd == LC_SEGMENT_64:
            name = bytes(data[off + 8:off + 24]).split(b"\x00")[0].decode("ascii", "replace")
            vmaddr = u64(data, off + 24)
            vmsize = u64(data, off + 32)
            fileoff = u64(data, off + 40)
            filesize = u64(data, off + 48)   # 48=filesize 56=maxprot/initprot
            nsects = u32(data, off + 64)
            segs.append((name, vmaddr, vmsize, fileoff, filesize, nsects, off))
            # 第一 sect 的 file offset
            first_sect = None
            sect_base = off + 72
            if nsects:
                first_sect = u32(data, sect_base + 48)  # offset 字段（相对 segment fileoff）
                first_sect_addr = u64(data, sect_base + 32)
                first_sect_size = u64(data, sect_base + 40)
            lcs.append(dict(kind="SEG", name=name, off=off, cmd=cmd,
                            fileoff=fileoff, filesize=filesize,
                            first_sect=first_sect, nsects=nsects,
                            first_sect_addr=first_sect_addr if nsects else None,
                            first_sect_size=first_sect_size if nsects else None))
            print(f"  [SEG] {name:<16} vmaddr=0x{vmaddr:x} vmsize=0x{vmsize:x} "
                  f"fileoff={fileoff} filesize={filesize} nsects={nsects}")
            if nsects:
                print(f"        first_sect sec_off={first_sect} → 绝对 fileoff={fileoff + first_sect}")
        elif cmd in LINKED_IT_LC:
            if cmd == LC_SYMTAB:
                symoff, nsyms, stroff, strsize = (u32(data, off + 8), u32(data, off + 12),
                                                  u32(data, off + 16), u32(data, off + 20))
                lcs.append(dict(kind="LC", cmd=cmd, off=off, dataoff=symoff,
                                end=symoff + nsyms * 16, extra=stroff + strsize))
                print(f"  [LC] {LINKED_IT_LC[cmd]} symoff={symoff} nsyms={nsyms} "
                      f"stroff={stroff} strsize={strsize}")
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                fo, fs_ = u32(data, off + 8), u32(data, off + 12)
                print(f"  [LC] {LINKED_IT_LC[cmd]} rebase={fo}/{fs_}")
                lcs.append(dict(kind="LC", cmd=cmd, off=off, dataoff=fo, end=fo + fs_))
            elif cmd == LC_CODE_SIGNATURE:
                do, ds = u32(data, off + 8), u32(data, off + 12)
                lcs.append(dict(kind="LC", cmd=cmd, off=off, dataoff=do, end=do + ds))
                print(f"  [LC] LC_CODE_SIGNATURE dataoff={do} datasize={ds} "
                      f"end={do+ds} {'✓贴尾' if do+ds == len(data) else '✗未贴尾'}")
            else:
                do, ds = u32(data, off + 8), u32(data, off + 12)
                lcs.append(dict(kind="LC", cmd=cmd, off=off, dataoff=do, end=do + ds))
                print(f"  [LC] {LINKED_IT_LC[cmd]} dataoff={do} datasize={ds} end={do+ds}")
        elif cmd == LC_DYSYMTAB:
            lcs.append(dict(kind="LC", cmd=cmd, off=off, dataoff=None, end=None))
            print(f"  [LC] LC_DYSYMTAB (含多个表偏移)")
        off += cs

    end_of_cmds = 32 + sizeofcmds
    print(f"  load command 链: 32..{end_of_cmds}  解析终点={off}  "
          f"{'✓闭合' if off == end_of_cmds else '✗不闭合'}")
    text = [s for s in segs if s[0] == "__TEXT"][0]
    le = [s for s in segs if s[0] == "__LINKEDIT"]
    # 第一个有内容的节的绝对偏移 vs load command 链终点
    first_content = text[3] + 0  # __TEXT.fileoff 通常是 0
    for name, vmaddr, vmsize, fileoff, filesize, nsects, o in segs:
        if nsects:
            sec_off = u32(data, o + 72 + 48)
            abs_off = fileoff + sec_off
            print(f"      首节 {name}/..  绝对 offset={abs_off} "
                  f"（距 cmds 链终点 {abs_off - end_of_cmds} 字节）")
            break
    if le:
        name, vmaddr, vmsize, fileoff, filesize, nsects, o = le[0]
        print(f"  __LINKEDIT: fileoff={fileoff} filesize={filesize} "
              f"end={fileoff+filesize}  实际文件长={len(data)} "
              f"差={len(data) - (fileoff + filesize)}")
    # 段之间是否连续无重叠
    ordered = sorted([s for s in segs if s[4] > 0], key=lambda s: s[3])
    prev_end = 0
    prev_name = "(start)"
    for name, vmaddr, vmsize, fileoff, filesize, nsects, o in ordered:
        if fileoff < prev_end:
            print(f"  !! 重叠: {name} fileoff={fileoff} < {prev_name} end={prev_end}")
        print(f"  段序 {prev_name:<14} end={prev_end:>10} → {name:<14} start={fileoff:>10} "
              f"gap={fileoff - prev_end}")
        prev_end = fileoff + filesize
        prev_name = name


for p in sys.argv[1:]:
    analyse(p)