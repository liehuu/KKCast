#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证明 verify_ipa.py 真的会失败。

为什么专门做这个：
  verify_ipa 的每一条都是"交付前最后一道门"。它一旦失效，产出的是
  一个 user 装不上的 ipa，而失败现场在手机上一片空白（没有日志）。
  所以每条判定都必须能被证明会失败。

做法：拿真实的 dist/kkys-dlna.ipa 当底包，逐条注入缺陷重打包，
断言校验器报 FAIL。这比造合成包可靠 —— 它验证的是真实产物路径。

覆盖：
  I1 基线（真实产物）                     → 期望 PASS
  I2 删掉 Frameworks/KKCast.dylib         → 期望 FAIL
  I3 dylib 改成空壳（<1KB）               → 期望 FAIL
  I4 dylib 的 cputype 改成 x86_64         → 期望 FAIL
  I5 抹掉可执行文件的 exec 位             → 期望 FAIL
  I6 首条目改成别的（不是 Payload/）       → 期望 FAIL
  I7 删掉 NSLocalNetworkUsageDescription  → 期望 FAIL
  I8 恢复一个 _CodeSignature/ 目录        → 期望 FAIL
  I9 删掉 Assets.car                      → 期望 FAIL
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def exe_arc_of(ipa):
    """从包里 Info.plist 的 CFBundleExecutable 精确定位主程序条目名。

    不能按"斜杠数 + 无扩展名"猜：movie.app 下 Assets.car / Info.plist /
    PkgInfo 深度一样，猜错就会拿 PNG 头去解 load command。
    """
    import plistlib
    with zipfile.ZipFile(ipa) as z:
        pl = [n for n in z.namelist()
              if n.startswith("Payload/") and n.endswith("/Info.plist")]
        if not pl:
            raise SystemExit(f"{ipa} 里没有 Payload/*/Info.plist")
        info = plistlib.loads(z.read(pl[0]))
        app_arc = pl[0][: -len("/Info.plist")]
        return f"{app_arc}/{info['CFBundleExecutable']}"
VERIFY = os.path.join(HERE, "verify_ipa.py")
PY = sys.executable

RESULTS = []


def rec(name, ok_, msg):
    RESULTS.append((name, ok_, msg))
    print(f"  {'✅' if ok_ else '❌'} {name}: {msg}")


def find_base():
    """底包必须是**当前正确产出**的包，否则整组反向用例的基线是坏的。

    旧顺序以 dist/kkys-dlna.ipa（v1，主程序 chained fixups 已损坏）打头，
    结果 I1「基线应 PASS」永远红 —— 而那不是判据失效，是底包本身有缺陷。
    现在优先取最新版本，并把 v1/v2 明确排除。

    ★ 顺序必须跟着"最新正确产出"走，否则每次出新版都要改这里。
      历史教训：
        - 指向 v1 → 主程序 chained fixups 坏 → I1 恒红
        - 指向 v2 → dylib chained fixups 坏 → I1 恒红
        - 指向 v3 → 能启动，但体积翻倍、代理逻辑有缺陷 → 基线不干净
      所以 v4 打头，逐级回退。
    """
    for cand in ("dist/kkys-dlna-v5.ipa",
                 "dist/kkys-dlna-v4.ipa",
                 "dist/kkys-dlna-v3.ipa",
                 "dist/kkys-dlna-v2.ipa",
                 "dist/kkys-dlna.ipa",
                 "dist-ci/kkys-dlna.ipa"):
        p = os.path.join(ROOT, cand)
        if os.path.exists(p):
            return p
    return None


def repack(src, dst, transform):
    """读 src，按 transform(name, data, info) -> (name, data, info|None) 重写 dst。

    transform 返回 None 表示丢弃该条目。
    """
    with zipfile.ZipFile(src) as zs:
        items = [(i, zs.read(i.filename)) for i in zs.infolist()]
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zd:
        for info, data in items:
            r = transform(info.filename, data, info)
            if r is None:
                continue
            name, d, ext = r
            zi = zipfile.ZipInfo(name)
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr if ext is None else ext
            zi.create_system = 3
            zd.writestr(zi, d)


def run_verify(path):
    p = subprocess.run([PY, VERIFY, path], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def case(name, base, transform, expect_pass=False):
    fd, tmp = tempfile.mkstemp(suffix=".ipa")
    os.close(fd)
    try:
        repack(base, tmp, transform)
        rc, out = run_verify(tmp)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    passed = (rc == 0)
    if passed == expect_pass:
        rec(name, True, f"期望 {'PASS' if expect_pass else 'FAIL'}，实际吻合")
    else:
        rec(name, False,
            f"期望 {'PASS' if expect_pass else 'FAIL'}，实际 "
            f"{'PASS' if passed else 'FAIL'} ← 判据没生效")
        print("      ----- 校验器输出尾部 -----")
        for line in out.strip().splitlines()[-14:]:
            print("      " + line)


def main():
    base = find_base()
    if not base:
        print("找不到 baseline ipa（先跑 build_ipa.py 产出 dist/kkys-dlna.ipa）")
        return 2

    print("=" * 62)
    print(f"verify_ipa.py 反向注入自检（底包 {os.path.relpath(base, ROOT)}）")
    print("=" * 62)

    print("\n--- I1 基线 ---")
    case("I1 基线", base, lambda n, d, i: (n, d, None), expect_pass=True)

    print("\n--- I2 删掉 Frameworks/KKCast.dylib ---")
    case("I2 缺 dylib", base,
         lambda n, d, i: None if n.endswith("Frameworks/KKCast.dylib") else (n, d, None))

    print("\n--- I3 dylib 空壳 ---")
    case("I3 dylib 空壳", base,
         lambda n, d, i: (n, d[:100], None) if n.endswith("Frameworks/KKCast.dylib")
         else (n, d, None))

    print("\n--- I4 dylib cputype 改 x86_64 ---")
    def i4(n, d, i):
        if n.endswith("Frameworks/KKCast.dylib"):
            b = bytearray(d)
            b[4:8] = struct.pack("<I", 0x01000007)
            return (n, bytes(b), None)
        return (n, d, None)
    case("I4 架构错", base, i4)

    print("\n--- I5 抹掉可执行文件的 exec 位 ---")
    def i5(n, d, i):
        if n.endswith(".app/movie") and n.count("/") == 2:
            return (n, d, 0o100644 << 16)
        return (n, d, None)
    case("I5 无 exec 位", base, i5)

    print("\n--- I6 首条目改成 Payload/movie.app/ ---")
    def i6(n, d, i):
        # 用重命名的办法让 Payload/ 不再是第一条：把一个 app 目录条目改名顶到最前
        if n == "Payload/":
            return ("AAA_first/", d, None)
        return (n, d, None)
    case("I6 首条目错", base, i6)

    print("\n--- I7 删掉 NSLocalNetworkUsageDescription ---")
    import plistlib

    def i7(n, d, i):
        if n.endswith(".app/Info.plist") and n.startswith("Payload/"):
            p = plistlib.loads(d)
            p.pop("NSLocalNetworkUsageDescription", None)
            return (n, plistlib.dumps(p), None)
        return (n, d, None)
    case("I7 缺局域网权限", base, i7)

    print("\n--- I8 恢复一个 _CodeSignature/ 目录 ---")
    def i8(n, d, i):
        if n == "Payload/":
            return (n, d, None)
        return (n, d, None)
    # 单独处理：先正常重打包，再追加目录条目
    def i8_pack(n, d, i):
        if n == "Payload/":
            return (n, d, None)
        return (n, d, None)
    fd, tmp = tempfile.mkstemp(suffix=".ipa")
    os.close(fd)
    try:
        repack(base, tmp, i8_pack)
        # 重新写一遍，插入 _CodeSignature/ 目录条目
        with zipfile.ZipFile(tmp) as zs:
            items = [(x, zs.read(x.filename)) for x in zs.infolist()]
        os.remove(tmp)
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zd:
            for info, data in items:
                zi = zipfile.ZipInfo(info.filename)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.create_system = 3
                zd.writestr(zi, data)
                if info.filename.endswith(".app/"):
                    zi2 = zipfile.ZipInfo(info.filename + "_CodeSignature/")
                    zi2.external_attr = (0o40755 << 16) | 0x10
                    zi2.create_system = 3
                    zd.writestr(zi2, b"")
        rc, out = run_verify(tmp)
        if rc == 0:
            rec("I8 残留签名目录", False, "期望 FAIL，实际 PASS ← 判据没生效")
        else:
            rec("I8 残留签名目录", True, "期望 FAIL，实际吻合")
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    print("\n--- I9 删掉 Assets.car ---")
    case("I9 缺 Assets.car", base,
         lambda n, d, i: None if n.endswith(".app/Assets.car") else (n, d, None))

    # ── I10 / I11：回放"位移"这一类真实缺陷 ──────────────────────
    #
    # 上面 I1~I9 测的都是"结构/缺失"类缺陷。真正让三轮真机都闪退的
    # 是**位移**类缺陷：结构完全合法、签名验得过、段不越界，但数据挪了。
    # 没有这两条，G 段那组判据就没有反向证据，等于装饰。
    #
    # 做法：把 package 里某个 Mach-O 的 chained fixups 起点整体后移 16 字节，
    # 模拟"插入式签名"的效果 —— dataoff 不改，内容错位。

    def shift_fixups(raw, delta=16):
        """把 chained fixups 之后的内容整体后移 delta，dataoff 不变。

        复刻 v2 的病：插入 16 字节但不更新任何引用。
        chained fixups 本身被推后，dyld 在原 dataoff 处读到零/错位数据。
        """
        sys.path.insert(0, HERE)
        import inject_dylib as INJ
        m = INJ.MachO(bytes(raw))
        off = m.header_size
        do = ds = None
        for _ in range(m.ncmds):
            if INJ.u32(raw, off) == 0x80000034:
                do = INJ.u32(raw, off + 8)
                ds = INJ.u32(raw, off + 12)
                break
            off += INJ.u32(raw, off + 4)
        if do is None or do + delta > len(raw):
            return raw
        d = bytearray(raw)
        # 在 do 处插入 delta 个零字节（不改任何 dataoff）
        d[do:do] = b"\x00" * delta
        return bytes(d)

    print("\n--- I10 主程序 chained fixups 被位移（回放 v1/v2 类缺陷）---")
    def i10_pack(n, d, i):
        if n == exe_arc_of(base):
            return n, shift_fixups(d), None
        return n, d, None
    case("I10 主程序位移", base, i10_pack)

    print("\n--- I11 dylib chained fixups 被位移（回放 v2 的真实病）---")
    def i11_pack(n, d, i):
        if n.endswith(".dylib"):
            return n, shift_fixups(d), None
        return n, d, None
    case("I11 dylib 位移", base, i11_pack)

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