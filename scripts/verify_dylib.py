#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验编译出来的 KKCast.dylib 是不是可用产物。

为什么必须读字节而不是看构建日志：
  xcodebuild 说 BUILD SUCCEEDED 只代表"没有编译错误"。
  它不代表产物是 arm64、是 iOS 平台、是 MH_DYLIB、
  或者里面真的有我们依赖的符号。这些都是装到手机上才暴露的问题，
  而到那时用户已经装了一次、崩了一次。

判定项：
  1. magic 是 MH_MAGIC_64（thin arm64，不是 fat，也不是 32 位）
  2. cputype == CPU_TYPE_ARM64
  3. filetype == MH_DYLIB(6)  —— 不是 MH_EXECUTE，不是 MH_BUNDLE
  4. LC_BUILD_VERSION.platform == 2(iOS) 或 LC_VERSION_MIN_IPHONEOS
  5. 导出表里有 _OBJC_CLASS_$_KKDLNA / _OBJC_CLASS_$_KKProxyServer /
     _OBJC_CLASS_$_KKCastUI，以及 constructor（__mod_init_func 非空）
  6. 没有 LC_ENCRYPTION_INFO（能编译出来就不可能加密，但若出现说明
     误链了别的二进制，属于严重错误）
"""

import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_DYLIB = 6
PLATFORMS = {1: "macOS", 2: "iOS", 3: "tvOS", 7: "iOSSimulator", 8: "tvOSSimulator"}

LC_SEGMENT_64 = 0x19
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_IPHONEOS = 0x25
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD

FAIL = []


def fail(m):
    FAIL.append(m)
    print(f"  ❌ {m}")


def ok(m):
    print(f"  ✅ {m}")


def u32(b, o):
    return struct.unpack("<I", b[o:o + 4])[0]


def u64(b, o):
    return struct.unpack("<Q", b[o:o + 8])[0]


def main():
    if len(sys.argv) < 2:
        raise SystemExit("用法: verify_dylib.py <KKCast.dylib>")

    path = sys.argv[1]
    with open(path, "rb") as f:
        d = f.read()

    print(f"文件: {path}")
    print(f"大小: {len(d)} 字节")
    print()

    if len(d) < 32:
        fail("文件太短")
        return 1

    magic = u32(d, 0)
    if magic == 0xCAFEBABE:
        fail("是 fat 二进制，应该是 thin arm64（构建参数少了 -arch arm64 或有多个 arch）")
        return 1
    if magic != MH_MAGIC_64:
        fail(f"magic=0x{magic:08x}，不是 MH_MAGIC_64")
        return 1
    ok(f"magic=0x{magic:08x} (MH_MAGIC_64, thin)")

    cputype = u32(d, 4)
    filetype = u32(d, 12)
    ncmds = u32(d, 16)

    if cputype == CPU_TYPE_ARM64:
        ok("cputype=arm64")
    else:
        fail(f"cputype=0x{cputype:08x}，不是 arm64")

    if filetype == MH_DYLIB:
        ok("filetype=MH_DYLIB(6)")
    else:
        # 这里必须**立刻退出**，不能继续往下解析。
        # 教训：dSYM 里的 DWARF 文件也叫 KKCast.dylib，filetype 是
        # MH_DSYM(10)，但它的 load command 结构完全合法，能一路解析到底，
        # 于是后面会连续报"没有 LC_ID_DYLIB""__mod_init_func 为空"——
        # 三条失败信息一起出现，看起来像编译把 dylib 编坏了，实际只是
        # 拿错了文件。root cause 只有一个，不该被三条症状盖住。
        fail(f"filetype={filetype}，应该是 6(MH_DYLIB)；"
             f"若是 10 说明拿到的是 dSYM 里的符号文件，不是 dylib 本体")
        print()
        print(f"结论：FAIL（{len(FAIL)} 项，filetype 不对，后续检查无意义）")
        return 1

    # 遍历 load command
    off = 32
    platform = None
    has_enc = False
    enc_detail = ""
    id_dylib = None
    deps = []
    segs = {}
    mod_init_size = None

    for _ in range(ncmds):
        if off + 8 > len(d):
            fail(f"load command 越界于 offset {off}")
            break
        cmd = u32(d, off)
        cs = u32(d, off + 4)
        if cs < 8:
            fail(f"cmdsize 异常 {cs} @ {off}")
            break

        if cmd == LC_BUILD_VERSION:
            platform = u32(d, off + 8)
            minos = u32(d, off + 12)
            print(f"  LC_BUILD_VERSION platform={platform} "
                  f"({PLATFORMS.get(platform,'?')}) minos={minos >> 16}.{(minos >> 8) & 255}")
        elif cmd == LC_VERSION_MIN_IPHONEOS:
            platform = 2
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
            # 只认 cryptid != 0。
            #
            # 这里踩过假 FAIL：链接器会给任何 iOS 二进制**无条件**写一条
            # LC_ENCRYPTION_INFO_64，cryptid=0 表示"未加密"。实测我们的
            # dylib 里就有这条：cryptoff=16384 cryptsize=65536 cryptid=0。
            # 早先的判据只要看到这条命令就报"误链了加密二进制"，把
            # 完全正常的产物判成不可用 —— 判据盯的是"命令存在"，
            # 而实际该盯的是"cryptid 是否为 0"。
            #
            # 字段布局（两者都是）：
            #   0 cmd(4) 4 cmdsize(4) 8 cryptoff(4) 12 cryptsize(4) 16 cryptid(4)
            cryptid = u32(d, off + 16)
            has_enc = (cryptid != 0)
            enc_detail = (f"cryptoff={u32(d, off + 8)} "
                          f"cryptsize={u32(d, off + 12)} cryptid={cryptid}")
        elif cmd == LC_ID_DYLIB:
            noff = u32(d, off + 8)
            id_dylib = d[off + noff:off + cs].split(b"\x00")[0].decode("utf-8", "replace")
        elif cmd == LC_LOAD_DYLIB:
            noff = u32(d, off + 8)
            deps.append(d[off + noff:off + cs].split(b"\x00")[0].decode("utf-8", "replace"))
        elif cmd == LC_SEGMENT_64:
            name = d[off + 8:off + 24].split(b"\x00")[0].decode("ascii", "replace")
            filesize = u64(d, off + 48)
            nsects = u32(d, off + 64)
            segs[name] = (filesize, nsects, off)

        off += cs

    if platform == 2:
        ok("platform=iOS")
    else:
        fail(f"platform={platform} ({PLATFORMS.get(platform,'?')})，应该编译成 iOS")

    if has_enc:
        fail(f"LC_ENCRYPTION_INFO 的 cryptid != 0（{enc_detail}）"
             f"→ 产物被加密，注入后 dyld 无法解密")
    else:
        ok(f"未加密（cryptid=0{'，有 LC_ENCRYPTION_INFO 但表示明文' if enc_detail else ''}）")

    if id_dylib:
        ok(f"LC_ID_DYLIB: {id_dylib}")
        if "KKCast" not in id_dylib:
            fail(f"dylib 安装名不含 KKCast：{id_dylib}（重命名会影响 @rpath 解析）")
    else:
        fail("没有 LC_ID_DYLIB，不是合法 dylib")

    # __mod_init_func 必须有内容 —— 我们的 hook 靠 constructor 安装
    #
    # 这段原本写成 `if "__DATA" in segs:` 包起来，是个**永真检查**：
    # 一旦段名不是精确的 "__DATA"（比如只有 __DATA_CONST，或者链接器
    # 改了布局），大括号里的全部逻辑静默跳过，一条都不报，最后仍然
    # 输出 PASS。而这一项恰恰决定"kkInstallHooks 会不会被调用"——
    # 它没跑就等于没验，注入上去必然完全没反应。
    #
    # 更关键的是**判据本身过时了**。实测 Xcode 16.4 / iphoneos 18.5 SDK
    # 编出来的 dylib 里根本没有 __DATA,__mod_init_func 这个节，constructor
    # 被放进了 __TEXT,__init_offsets（配合 LC_DYLD_CHAINED_FIXUPS）。
    # 证据（真实产物 dist-ci 里那份）：
    #   __TEXT,__init_offsets  addr=0xedc0 size=4  flags=0x16
    #   raw = 78 40 00 00 → int32 16504 = 0x4078
    #   __TEXT,__text          addr=0x4000
    # 0x4078 落在 __text 内，正是一个函数入口。也就是说 constructor
    # **确实生成了**，只是换了节名。旧判据只认 __mod_init_func，
    # 于是把"完全正常"判成"constructor 没生成"——这是假 FAIL，
    # 比漏报更误导人（会让人去改源码，而源码本来就是对的）。
    #
    # 所以两种布局都要认，并且区分"节不存在"与"节存在但为空"。
    MODINIT_SECTIONS = ("__mod_init_func", "__init_offsets")

    def scan_section(sect_name):
        """返回 (found, size, seg_name, address, fileoff)。"""
        for seg_name, (filesize, nsects, coff) in segs.items():
            if nsects == 0:
                continue
            o = coff + 72  # segment_command_64 头 72 字节，之后是 section_64 数组
            for _ in range(nsects):
                if o + 80 > len(d):
                    break
                sname = d[o:o + 16].split(b"\x00")[0].decode("ascii", "replace")
                if sname == sect_name:
                    addr = u64(d, o + 32)
                    size = u64(d, o + 40)
                    foff = u32(d, o + 48)
                    return True, size, seg_name, addr, foff
                o += 80
        return False, 0, None, 0, 0

    found_modinit = False
    mod_init_size = None
    mod_init_seg = None
    mod_init_sect = None

    for candidate in MODINIT_SECTIONS:
        f, sz, sg, addr, foff = scan_section(candidate)
        if f:
            found_modinit = True
            mod_init_size = sz
            mod_init_seg = sg
            mod_init_sect = candidate
            # 对 __init_offsets 再做一层实质校验：里面的每个 int32 应该是
            # 相对 __TEXT 的偏移，落在 __TEXT 范围内。全零或越界说明
            # 这个节只是占位，constructor 实际没挂上。
            if candidate == "__init_offsets" and sz >= 4:
                text_addr = 0
                for sgn, (fs, ns, co) in segs.items():
                    if sgn == "__TEXT":
                        text_addr = u64(d, co + 24)   # vmaddr
                        text_vmsize = u64(d, co + 32)  # vmsize
                        break
                bad_entries = 0
                entries = sz // 4
                for j in range(entries):
                    pos = foff + j * 4
                    if pos + 4 > len(d):
                        bad_entries += 1
                        continue
                    v = u32(d, pos)
                    if v == 0 or not (text_addr <= text_addr + v < text_addr + text_vmsize):
                        bad_entries += 1
                if bad_entries:
                    fail(f"__init_offsets 有 {bad_entries}/{entries} 个条目指向 "
                         f"__TEXT 之外或为 0 → constructor 没真正挂上")
                else:
                    ok(f"__init_offsets 有 {entries} 个有效条目，均落在 __TEXT 内")
            break

    if found_modinit and mod_init_size and mod_init_size > 0:
        ok(f"{mod_init_sect} 有内容（{mod_init_size} 字节，在 {mod_init_seg}）"
           f"→ constructor 会执行")
    elif found_modinit:
        fail(f"{mod_init_sect} 存在但大小为 {mod_init_size} → kkInstallHooks "
             f"不会被调用（constructor 被 dead-strip 了？检查 DEAD_CODE_STRIPPING）")
    else:
        fail("既没有 __mod_init_func 也没有 __init_offsets → constructor "
             "完全没生成，注入后不会有任何反应")

    # 依赖里不能有 Swift 运行时（我们是纯 ObjC，多链 Swift 会拖慢启动
    # 并可能和宿主的 Swift 版本冲突）
    swift_deps = [x for x in deps if "swift" in x.lower()]
    if swift_deps:
        print(f"  ⚠️  链了 Swift 运行时：{swift_deps}")
    else:
        ok("未链接 Swift 运行时（纯 ObjC，与宿主无冲突风险）")

    # 检查导出的 ObjC 类符号
    # 没有 nm 就退化成查字符串：__cstring / __objc_classname 里应有类名。
    # 这不是最严谨的方式，但 nm 不可用时聊胜于无，且能抓"编译成功但
    # 类被 -dead_strip 干掉"的情况。
    need = [b"KKDLNA", b"KKProxyServer", b"KKCastUI", b"KKCastDevice"]
    for n in need:
        if n in d:
            ok(f"符号/类名存在: {n.decode()}")
        else:
            fail(f"找不到 {n.decode()} —— 类可能被 dead-strip 或没参与编译")

    print()
    if FAIL:
        print(f"结论：FAIL（{len(FAIL)} 项）")
        return 1
    print("结论：PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())