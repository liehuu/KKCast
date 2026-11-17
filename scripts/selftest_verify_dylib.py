#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证明 verify_dylib.py 真的会失败 —— 而不是永远输出 PASS。

为什么需要这个：
  verify_dylib 的三处判定曾经都是**永真检查**，实测代价是一条真实的
  CI 失败被误读成"编译把 dylib 编坏了"：

    if "__DATA" in segs:            # 段名不叫 __DATA 就整段跳过
        ...__mod_init_func 检查...   # 跳过后依然输出 PASS

  这类检查比没有检查更糟：它给出"验过了"的错觉。

做法：
  用结构已知的合成 MH_DYLIB 当样本（不是复制实现，是按 Mach-O 规范
  构造字节），然后逐个注入缺陷，断言校验器确实报 FAIL。
  同时有一个"全部合法"的基线，断言基线为 PASS —— 否则下面所有
  FAIL 都可能只是校验器整体坏掉，属于假 FAIL。

覆盖：
  G1 基线（合法 dylib，旧布局 __DATA,__mod_init_func）  → 期望 PASS
  G1b 基线确实跑到了 constructor 检查（防空测）
  G2 filetype 改成 MH_DSYM(10)     → 期望 FAIL 且只报 1 条（立刻退出）
  G3 完全没有 constructor 节       → 期望 FAIL（不能静默跳过）
  G4 constructor 节大小为 0        → 期望 FAIL
  G5 constructor 在 __DATA_CONST 里 → 期望 PASS（段名不该写死）
  G6 cputype 改成 x86_64           → 期望 FAIL
  G7a cryptid=0（新布局的常态）     → 期望 PASS（不能因为命令存在就报错）
  G7b cryptid=1（真的加密了）       → 期望 FAIL
  G8 删掉 LC_ID_DYLIB              → 期望 FAIL
  G9 __init_offsets 新布局，条目有效 → 期望 PASS
  G10 __init_offsets 条目为 0       → 期望 FAIL
  G11 __init_offsets 条目越界       → 期望 FAIL

  G7a/G9 这两个 PASS 用例是必须的：它们对应的判据曾经都写成"只要
  看到特征就报错"，把完全正常的产物判成不可用。如果只保留 FAIL 用例，
  就会在"修掉漏报"的同时引入误报，而误报同样会让人去改本来正确的代码。
"""

import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
VERIFY = os.path.join(HERE, "verify_dylib.py")
PY = sys.executable

LC_SEGMENT_64 = 0x19
LC_BUILD_VERSION = 0x32
LC_ID_DYLIB = 0xD
LC_ENCRYPTION_INFO_64 = 0x2C

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007

RESULTS = []


def rec(name, ok_, msg):
    RESULTS.append((name, ok_, msg))
    print(f"  {'✅' if ok_ else '❌'} {name}: {msg}")


def p32(v):
    return struct.pack("<I", v)


def p64(v):
    return struct.pack("<Q", v)


def sec(name, addr, size, offset):
    """section_64 = 80 字节。

    布局：0 sectname(16) 16 segname(16) 32 addr(8) 40 size(8)
          48 offset(4) 52 align(4) 56 reloff(4) 60 nreloc(4)
          64 flags(4) 68 reserved1(4) 72 reserved2(4) 76 reserved3(4)
    注意 size 在偏移 40（不是 32），offset 在 48。
    """
    b = name.encode().ljust(16, b"\x00")
    b += b"\x00" * 16              # segname
    b += p64(addr) + p64(size)
    b += p32(offset) + p32(2) + p32(0) + p32(0)
    b += p32(0x80000400) + p32(0) + p32(0) + p32(0)
    assert len(b) == 80, len(b)
    return b


def seg(name, vmaddr, vmsize, fileoff, filesize, sections):
    """segment_command_64：头 72 字节 + 80*n 个 section。"""
    cmdsize = 72 + 80 * len(sections)
    b = p32(LC_SEGMENT_64) + p32(cmdsize) + name.encode().ljust(16, b"\x00")
    b += p64(vmaddr) + p64(vmsize) + p64(fileoff) + p64(filesize)
    b += p32(7) + p32(5) + p32(len(sections)) + p32(0)   # maxprot initprot nsects flags
    assert len(b) == 72, len(b)
    for s in sections:
        b += s
    return b


def build(seg_name_for_modinit="__DATA", modinit_size=8,
          filetype=6, cputype=CPU_TYPE_ARM64, with_id_dylib=True,
          cryptid=None, new_layout=False, init_offset_value=None):
    """构造一个布局自洽的最小 MH_DYLIB。

    关键：所有段/节的 fileoff 必须落在文件内，否则校验器会先报越界，
    后续判定就测不到了。这里用真实的文件偏移排布。

    两套布局都要能造，因为真实产物用的是新布局：
      new_layout=False → 旧布局：__DATA,__mod_init_func（8 字节指针数组）
      new_layout=True  → 新布局：__TEXT,__init_offsets（int32 相对偏移）
    实测 Xcode 16.4 + chained fixups 编出来的是新布局，只认旧布局的
    判据会把正常产物判死。

    cryptid: None=不发 LC_ENCRYPTION_INFO；0=发但明文；1=真的加密。
    """
    TEXT_OFF = 0x1000
    TEXT_SZ = 0x400
    DATA_OFF = 0x2000
    DATA_SZ = 0x400

    TEXT_VMADDR = 0x1000
    DATA_VMADDR = 0x2000

    text_sec = sec("__text", TEXT_VMADDR, TEXT_SZ, TEXT_OFF)

    if new_layout:
        # __init_offsets 的条目是「相对 __TEXT 的 int32 偏移」。
        # 给个默认值让它落在 __text 里（偏移 0x20 → vmaddr 0x1020）。
        n_entries = max(1, modinit_size // 4)
        vals = []
        for j in range(n_entries):
            if init_offset_value is not None:
                vals.append(init_offset_value)
            else:
                vals.append(0x20 + j * 4)
        offsets_blob = b"".join(struct.pack("<I", v & 0xFFFFFFFF) for v in vals)
        if seg_name_for_modinit is None:
            text_sections = [text_sec]
        else:
            text_sections = [text_sec, sec("__init_offsets",
                                           TEXT_VMADDR + 0x200,
                                           len(offsets_blob),
                                           TEXT_OFF + 0x200)]
        segs = [seg("__TEXT", TEXT_VMADDR, 0x1000, 0, TEXT_OFF + TEXT_SZ,
                    text_sections)]
        segs.append(seg("__DATA", DATA_VMADDR, 0x1000, DATA_OFF,
                        DATA_OFF + DATA_SZ, []))
        const_sec = None
        modinit_sec = None
    else:
        offsets_blob = None
        modinit_sec = sec("__mod_init_func", DATA_VMADDR, modinit_size, DATA_OFF)
        const_sec = sec("__const", DATA_VMADDR, modinit_size, DATA_OFF)
        segs = [seg("__TEXT", TEXT_VMADDR, 0x1000, 0, TEXT_OFF + TEXT_SZ,
                    [text_sec])]
        if seg_name_for_modinit == "__DATA_CONST":
            segs.append(seg("__DATA_CONST", DATA_VMADDR, 0x1000, DATA_OFF,
                            DATA_OFF + DATA_SZ, [modinit_sec, const_sec]))
            segs.append(seg("__DATA", 0x3000, 0x1000, 0, 0, []))
        elif seg_name_for_modinit is None:
            # 完全没有 constructor 节：__DATA 里只放一个无关的节
            segs.append(seg("__DATA", DATA_VMADDR, 0x1000, DATA_OFF,
                            DATA_OFF + DATA_SZ, [const_sec]))
        else:
            segs.append(seg("__DATA", DATA_VMADDR, 0x1000, DATA_OFF,
                            DATA_OFF + DATA_SZ, [modinit_sec]))

    cmds = list(segs)

    # LC_BUILD_VERSION: platform=iOS(2), minos=14.0
    cmds.append(p32(LC_BUILD_VERSION) + p32(24) + p32(2) + p32(0x000E0000)
                + p32(0x000E0000) + p32(0))

    if with_id_dylib:
        nm = b"@rpath/KKCast.dylib\x00"
        cs = 24 + len(nm)
        b = p32(LC_ID_DYLIB) + p32((cs + 7) // 8 * 8) + p32(24)
        b += p32(1) + p32(1) + p32(1) + nm
        b += b"\x00" * (((cs + 7) // 8 * 8) - cs)
        cmds.append(b)

    if cryptid is not None:
        # cryptoff/cryptsize 指向 __TEXT 内部，cryptid 决定是否加密。
        cmds.append(p32(LC_ENCRYPTION_INFO_64) + p32(24) + p32(TEXT_OFF)
                    + p32(TEXT_SZ) + p32(cryptid) + p32(0))

    body = b"".join(cmds)
    sizeofcmds = len(body)

    hdr = p32(MH_MAGIC_64) + p32(cputype) + p32(0) + p32(filetype)
    hdr += p32(len(cmds)) + p32(sizeofcmds) + p32(0) + p32(0)

    # 文件长度必须覆盖所有节的 fileoff+size，否则校验器会先报越界，
    # 后续判定根本测不到（这就是下面 IndexError 的由来）。
    total = max(TEXT_OFF + TEXT_SZ, DATA_OFF + DATA_SZ)
    buf = bytearray(total)
    buf[0:32] = hdr
    buf[32:32 + sizeofcmds] = body

    # 校验器会查类名字符串是否存在（抓"编译成功但类被 dead-strip"的情况）。
    # 合成样本里必须真的放进去，否则基线会因为这 4 条而 FAIL，
    # 掩盖掉我们真正想测的项。放进 __TEXT 里（真实 dylib 里类名在
    # __objc_classname/__cstring，都属于 __TEXT）。
    names = b"\x00".join([b"KKDLNA", b"KKProxyServer", b"KKCastUI",
                          b"KKCastDevice"]) + b"\x00"
    buf[TEXT_OFF:TEXT_OFF + len(names)] = names

    # 填一点内容，让 __mod_init_func 的 offset 指向真实字节
    for i in range(DATA_OFF, min(DATA_OFF + 8, total)):
        buf[i] = 0xAB

    # 新布局：__init_offsets 的内容必须真的写进去，否则校验器读到全零
    # 会判"条目无效"，基线就 FAIL 了，测不到别的项。
    if offsets_blob is not None:
        pos = TEXT_OFF + 0x200
        buf[pos:pos + len(offsets_blob)] = offsets_blob

    return bytes(buf)


def run_verify(path):
    p = subprocess.run([PY, VERIFY, path], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def check(name, data, expect_pass, expect_fail_count=None):
    fd, path = tempfile.mkstemp(suffix=".dylib")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        rc, out = run_verify(path)
    finally:
        os.unlink(path)
    passed = (rc == 0)
    okflag = (passed == expect_pass)
    detail = f"期望 {'PASS' if expect_pass else 'FAIL'}，实际 {'PASS' if passed else 'FAIL'}"
    if not okflag:
        rec(name, False, detail + " ← 判据没生效")
        print("      ----- 校验器输出 -----")
        for line in out.strip().splitlines()[-12:]:
            print("      " + line)
        return out
    if expect_fail_count is not None and not expect_pass:
        n = out.count("  ❌")
        if n != expect_fail_count:
            rec(name, False, f"{detail}，但报了 {n} 条失败，期望 {expect_fail_count} 条")
            return out
        rec(name, True, f"{detail}，失败条数 {n}（符合预期）")
    else:
        rec(name, True, detail)
    return out


def main():
    print("=" * 62)
    print("verify_dylib.py 反向注入自检")
    print("=" * 62)

    print("\n--- G1 基线（旧布局 __DATA,__mod_init_func） ---")
    out = check("G1 基线", build(), expect_pass=True)
    # 基线必须真的跑到 constructor 那一条，否则下面的 G3/G4 是空测
    if "__mod_init_func 有内容" not in out:
        rec("G1b 基线覆盖 constructor 检查", False,
            "基线没跑到 constructor 检查 —— G3/G4 测的是不存在的路径")
    else:
        rec("G1b 基线覆盖 constructor 检查", True, "基线确实检查了 __mod_init_func")

    print("\n--- G2 filetype=MH_DSYM(10)：必须立刻退出 ---")
    check("G2 dSYM 文件", build(filetype=10), expect_pass=False, expect_fail_count=1)

    print("\n--- G3 完全没有 constructor 节：不能静默跳过 ---")
    check("G3 缺 constructor 节", build(seg_name_for_modinit=None), expect_pass=False)

    print("\n--- G4 constructor 节大小为 0 ---")
    check("G4 size=0", build(modinit_size=0), expect_pass=False)

    print("\n--- G5 constructor 在 __DATA_CONST：段名不该写死 ---")
    check("G5 在 __DATA_CONST", build(seg_name_for_modinit="__DATA_CONST"),
          expect_pass=True)

    print("\n--- G6 cputype=x86_64 ---")
    check("G6 x86_64", build(cputype=CPU_TYPE_X86_64), expect_pass=False)

    print("\n--- G7a cryptid=0（新布局常态，不能报错） ---")
    check("G7a cryptid=0", build(cryptid=0), expect_pass=True)

    print("\n--- G7b cryptid=1（真的加密了） ---")
    check("G7b cryptid=1", build(cryptid=1), expect_pass=False)

    print("\n--- G8 没有 LC_ID_DYLIB ---")
    check("G8 缺 ID_DYLIB", build(with_id_dylib=False), expect_pass=False)

    print("\n--- G9 新布局 __TEXT,__init_offsets（真实产物的布局） ---")
    out = check("G9 __init_offsets 有效", build(new_layout=True, modinit_size=4),
                expect_pass=True)
    if "__init_offsets 有内容" not in out:
        rec("G9b 基线覆盖 __init_offsets", False,
            "没走到 __init_offsets 判定 —— G10/G11 是空测")
    else:
        rec("G9b 基线覆盖 __init_offsets", True, "确实走了 __init_offsets 判定")

    print("\n--- G10 __init_offsets 条目为 0（占位但没挂函数） ---")
    check("G10 条目为 0", build(new_layout=True, modinit_size=4,
                                init_offset_value=0), expect_pass=False)

    print("\n--- G11 __init_offsets 条目越界 ---")
    check("G11 条目越界", build(new_layout=True, modinit_size=4,
                                init_offset_value=0x7000), expect_pass=False)

    print()
    print("=" * 62)
    bad = [r for r in RESULTS if not r[1]]
    if bad:
        print(f"结论：FAIL（{len(bad)}/{len(RESULTS)} 项）")
        for n, _, m in bad:
            print(f"  ❌ {n}: {m}")
        return 1
    print(f"结论：PASS（{len(RESULTS)}/{len(RESULTS)} 项）")
    return 0


if __name__ == "__main__":
    sys.exit(main())