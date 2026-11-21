#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析 Mach-O 的未定义外部符号 + 加密状态。

判据：dyld 加载 dylib 时，任何一条 N_UNDF 外部符号在
(宿主可执行文件 + 已加载系统库) 里找不到，就 abort：
    dyld: Symbol not found: _xxx
    Referenced from: .../Frameworks/KKCast.dylib
这个崩溃发生在进程启动早期，表现是"进入画面就闪退"，
和 CodeSignature 被拒的外观无法区分。必须逐条列出符号，
不能只看"依赖库列表看起来都是系统库"就下结论。

同时检查 LC_ENCRYPTION_INFO_64 的 cryptid：
  cryptid != 0 = App Store 加密二进制，未解密就装必闪退。
"""
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_SYMTAB = 0x2
LC_ENCRYPTION_INFO_64 = 0x2C
LC_ENCRYPTION_INFO = 0x21

N_STAB = 0xE0
N_PEXT = 0x10
N_TYPE = 0x0E
N_EXT = 0x01
N_UNDF = 0x0
N_SECT = 0xE
N_ABS = 0x2


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def analyse(path):
    d = open(path, "rb").read()
    print(f"\n=== {os.path.basename(path) if (os := __import__('os')) else path} ===")
    print(f"  size={len(d)} magic=0x{u32(d, 0):08x}")
    ncmds = u32(d, 16)
    off = 32
    symtab = None
    crypt = None
    for _ in range(ncmds):
        cmd, cs = u32(d, off), u32(d, off + 4)
        if cmd == LC_SYMTAB:
            symtab = (u32(d, off + 8), u32(d, off + 12),
                      u32(d, off + 16), u32(d, off + 20))
        elif cmd == LC_ENCRYPTION_INFO_64:
            crypt = (u32(d, off + 8), u32(d, off + 12), u32(d, off + 16))
        elif cmd == LC_ENCRYPTION_INFO:
            crypt = (u32(d, off + 8), u32(d, off + 12), u32(d, off + 16))
        off += cs

    if crypt:
        cdoff, cssize, cryptid = crypt
        print(f"  LC_ENCRYPTION_INFO cryptoff={cdoff} cryptsize={cssize} "
              f"cryptid={cryptid}  "
              f"{'✓ 已解密' if cryptid == 0 else '❌ 仍加密，未解密装上去必闪退'}")
    else:
        print("  LC_ENCRYPTION_INFO: 不存在（未加密）✓")

    if not symtab:
        print("  !! 无 LC_SYMTAB（已 strip？）")
        return None
    symoff, nsyms, stroff, strsize = symtab
    print(f"  LC_SYMTAB symoff={symoff} nsyms={nsyms} stroff={stroff} strsize={strsize}")
    if symoff + nsyms * 16 > len(d):
        print("  !! symtab 越界")
        return None

    undef_ext = []
    undef_local = []
    defs = 0
    for i in range(nsyms):
        p = symoff + i * 16
        n_strx = u32(d, p)
        n_type = d[p + 4]
        n_sect = d[p + 5]
        n_desc = struct.unpack_from("<H", d, p + 6)[0]
        if n_strx == 0:
            continue
        pos = stroff + n_strx
        if pos >= len(d) or n_strx >= strsize:
            # 索引越界本身就是二进制缺陷，不能静默跳过
            undef_ext.append((f"<string index out of range: {n_strx}>", 0xFFFF))
            continue
        e = d.find(b"\x00", pos)
        if e < 0:
            undef_ext.append((f"<unterminated string at {pos}>", 0xFFFF))
            continue
        name = d[pos:e].decode("utf-8", "replace")
        if n_type & N_STAB:
            continue
        t = n_type & N_TYPE
        if t == N_UNDF:
            if n_type & N_EXT:
                undef_ext.append((name, n_desc))
            else:
                undef_local.append((name, n_desc))
        else:
            defs += 1

    print(f"  已定义符号 {defs} 个")
    print(f"  未定义外部符号 {len(undef_ext)} 个：" + ("（dyld 必须逐个解析，任一缺失即 abort）" if undef_ext else ""))
    for name, desc in undef_ext:
        kind = "weak" if (desc & 0x0001) or (desc & 0x0040) else "strong"
        print(f"    [{kind:6}] {name}")
    if undef_local:
        print(f"  未定义本地符号 {len(undef_local)} 个（异常，通常为 0）")
        for name, _ in undef_local[:10]:
            print(f"    {name}")
    return undef_ext


for p in sys.argv[1:]:
    analyse(p)