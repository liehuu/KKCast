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
        fail(f"filetype={filetype}，应该是 6(MH_DYLIB)")

    # 遍历 load command
    off = 32
    platform = None
    has_enc = False
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
            has_enc = True
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
        fail("出现 LC_ENCRYPTION_INFO —— 说明误链了加密二进制，产物不可用")
    else:
        ok("无加密段")

    if id_dylib:
        ok(f"LC_ID_DYLIB: {id_dylib}")
        if "KKCast" not in id_dylib:
            fail(f"dylib 安装名不含 KKCast：{id_dylib}（重命名会影响 @rpath 解析）")
    else:
        fail("没有 LC_ID_DYLIB，不是合法 dylib")

    # __mod_init_func 必须有内容 —— 我们的 hook 靠 constructor 安装
    if "__DATA" in segs:
        filesize, nsects, coff = segs["__DATA"]
        found_modinit = False
        o = coff + 72
        for _ in range(nsects):
            sname = d[o:o + 16].split(b"\x00")[0].decode("ascii", "replace")
            size = u64(d, o + 40)
            if sname == "__mod_init_func":
                found_modinit = True
                mod_init_size = size
            o += 80
        if found_modinit and mod_init_size and mod_init_size > 0:
            ok(f"__mod_init_func 有内容（{mod_init_size} 字节）→ constructor 会执行")
        else:
            fail("__mod_init_func 为空 → kkInstallHooks 不会被调用，注入后完全没反应")

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