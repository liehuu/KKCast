#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 LC_DYLD_CHAINED_FIXUPS 的导入表 —— dyld 真正用来绑定符号的数据源。

为什么必须读这里而不是 symtab：
  已 strip 的二进制 symtab 可能不完整/不可靠；dyld 在 iOS 15+ 上走的是
  chained fixups。任何一条导入的 library ordinal 越界、或符号在对应
  库里不存在，dyld 会直接 abort：
      dyld: Symbol not found: _xxx
      Referenced from: /var/.../Frameworks/KKCast.dylib
  这个失败发生在 main() 之前，表现就是"出现进入画面就闪退"。

关键格式（全部 little-endian，偏移相对 fixups blob 起点）：
  dyld_chained_fixups_header {
    uint32 fixups_version, starts_offset, imports_offset,
           symbols_offset, imports_count, imports_format, symbols_format;
  }
  imports_format 1 (DYLD_CHAINED_IMPORT): uint32 位域
      lib_ordinal:8 | weak_import:1 | name_offset:23
  lib_ordinal 语义：0=自身 0xFF=主程序 0xFE=flat lookup 1..N=第 N 个依赖库
"""
import struct
import sys
import zlib

LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_LAZY_LOAD_DYLIB = 0x80000020

DYLIB_CMDS = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
              LC_LOAD_UPWARD_DYLIB, LC_LAZY_LOAD_DYLIB}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def analyse(path):
    d = open(path, "rb").read()
    print(f"\n{'='*70}\n{path}\n{'='*70}")
    ncmds = u32(d, 16)
    off = 32
    dylibs = [None]          # 1-based，与 lib_ordinal 对齐
    chained = None
    dyldinfo = None
    linkedit = None
    for _ in range(ncmds):
        cmd, cs = u32(d, off), u32(d, off + 4)
        if cmd in DYLIB_CMDS:
            noff = u32(d, off + 8)
            nm = d[off + noff:off + cs].split(b"\x00")[0].decode("utf-8", "replace")
            dylibs.append(nm)
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            chained = (u32(d, off + 8), u32(d, off + 12))
        elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
            dyldinfo = (u32(d, off + 8), u32(d, off + 12))  # rebase off/size
        elif cmd == LC_SEGMENT_64:
            name = d[off + 8:off + 24].split(b"\x00")[0].decode("ascii", "replace")
            if name == "__LINKEDIT":
                linkedit = (u64(d, off + 40), u64(d, off + 48), u64(d, off + 24))
        off += cs

    print(f"依赖库 {len(dylibs)-1} 个：")
    for i, nm in enumerate(dylibs[1:], 1):
        print(f"  [{i}] {nm}")

    if not chained:
        print("\n无 LC_DYLD_CHAINED_FIXUPS —— 走旧式 LC_DYLD_INFO bind")
        if dyldinfo:
            print(f"  LC_DYLD_INFO bind_off={dyldinfo[0]} bind_size={dyldinfo[1]}")
            print("  （旧式 bind opcode 需逐条遍历，本脚本暂不解析；"
                  "若存在此项则归属 dyld 老路径）")
        return

    dataoff, datasize = chained
    print(f"\nLC_DYLD_CHAINED_FIXUPS dataoff={dataoff} datasize={datasize}")
    # blob 起点 = __LINKEDIT.fileoff + dataoff（dataoff 是相对文件头的绝对偏移，
    # 实际上 dataoff 已经是文件内绝对偏移，等于 linkedit.fileoff + 段内偏移）
    base = dataoff
    hdr = struct.unpack_from("<IIIIIII", d, base)
    (fixups_version, starts_off, imports_off, symbols_off,
     imports_count, imports_format, symbols_format) = hdr
    print(f"  fixups_version={fixups_version} imports_count={imports_count} "
          f"imports_format={imports_format} symbols_format={symbols_format}")

    if imports_count == 0:
        print("  导入 0 条 —— 该镜像不依赖外部符号（不太可能，需复查）")
        return

    # 字符串表
    sym_base = base + symbols_off
    if symbols_format == 1:      # zlib
        # symbols 区从 sym_base 到 blob 结尾，前 4 字节是解压后大小
        raw = d[sym_base:base + datasize]
        usize = struct.unpack_from("<I", raw, 0)[0]
        strtab = zlib.decompress(raw[4:])
        print(f"  符号表 zlib 解压 {len(strtab)} 字节（声明 {usize}）")
    else:
        strtab = d[sym_base:base + datasize]

    def name_at(o):
        if o >= len(strtab):
            return f"<越界 {o}>"
        e = strtab.find(b"\x00", o)
        if e < 0:
            return f"<未终止 {o}>"
        return strtab[o:e].decode("utf-8", "replace")

    bad = []
    weak_cnt = 0
    print(f"\n逐条校验 {imports_count} 条导入（lib_ordinal 必须 <= {len(dylibs)-1}）")
    for i in range(imports_count):
        p = base + imports_off + i * 4
        raw = u32(d, p)
        if imports_format == 1:
            lib_ord = raw & 0xFF
            weak = (raw >> 8) & 1
            name_off = (raw >> 9) & 0x7FFFFF
        elif imports_format == 2:
            lib_ord = raw & 0xFF
            weak = (raw >> 8) & 1
            name_off = (raw >> 9) & 0x7FFFFF
        else:
            print(f"  imports_format={imports_format} 不支持")
            return
        nm = name_at(name_off)
        if weak:
            weak_cnt += 1
        special = {0: "self", 0xFE: "flat", 0xFF: "main-exec"}
        if lib_ord in special:
            libname = special[lib_ord]
            ok = True
        elif 1 <= lib_ord < len(dylibs):
            libname = dylibs[lib_ord]
            ok = True
        else:
            libname = f"!! ordinal {lib_ord} 越界"
            ok = False
        if not ok:
            bad.append((i, lib_ord, nm))
        print(f"  [{i:3}] ord={lib_ord:3} ({libname:<52.52}) "
              f"{'weak ' if weak else '     '} {nm}")

    print(f"\n结论：weak 导入 {weak_cnt} 条")
    if bad:
        print(f"❌ {len(bad)} 条导入的 library ordinal 越界 —— dyld 必然 abort：")
        for i, o, nm in bad:
            print(f"   #{i} ord={o} {nm}")
    else:
        print("✅ 全部导入的 library ordinal 在依赖库范围内")

    # __LINKEDIT 必须覆盖整个 fixups blob
    if linkedit:
        fo, fs, vmaddr = linkedit
        end = fo + fs
        need = dataoff + datasize
        print(f"\n__LINKEDIT fileoff={fo} filesize={fs} end={end}")
        print(f"fixups blob 需要覆盖到 {need}  "
              f"{'✅' if end >= need else '❌ 超出 __LINKEDIT，dyld 读不到'}")


for p in sys.argv[1:]:
    analyse(p)