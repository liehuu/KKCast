#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验最终 ipa：改动是否真的在包里。

这一层和前面几层的区别：
  门禁 1~3 校验的是**源文件和中间产物**。它们全绿，也不代表
  最终 zip 里装的是那个产物。UnCast 那次就是靠"产物差分"才发现
  某处修改没进包——CI 全绿，装到电视上却没有那个行为。

  所以这里只认最终 ipa 里的字节，不认任何构建声明。

判定项：
  A. dylib 存在且大小 > 1KB（不是空壳）
  B. dylib 本身是合法 arm64 MH_DYLIB（不是误拷了别的架构）
  C. 可执行文件里有 LC_LOAD_DYLIB 指向我们的 dylib
  D. 可执行文件与注入 dylib 都带**合法 ad-hoc 签名**（page hash 全量复核）
     —— 旧判据反过来要求"没有 LC_CODE_SIGNATURE"，结果裸 Mach-O 一路
        过检、装上手机点开就 abort。TrollStore 不替裸 Mach-O 造签名。
  E. Info.plist 有 NSLocalNetworkUsageDescription 且非空
  F. _CodeSignature 目录已删除（包级旧签名，与 Mach-O 内签名是两回事）
  G. 可执行文件的 __LINKEDIT 仍完整（截断没截过头）
"""

import os
import plistlib
import struct
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adhoc_sign  # noqa: E402
import inject_dylib  # noqa: E402

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_BUILD_VERSION = 0x32

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


def _walk_offsets(raw, m):
    """按命令链返回每条 load command 的起始偏移。

    单独写一个而不是复用 inject_dylib 的内部实现：这里有两条独立的
    解析路径，任一条读错都会被另一条的断言暴露。
    """
    off = m.header_size
    out = []
    for _ in range(m.ncmds):
        if off + 8 > len(raw):
            break
        cs = u32(raw, off + 4)
        if cs < 8:
            break
        out.append(off)
        off += cs
    return out


def main():
    if len(sys.argv) < 2:
        raise SystemExit("用法: verify_ipa.py <ipa>")
    ipa = sys.argv[1]
    print(f"文件: {ipa}  ({os.path.getsize(ipa)} 字节)")
    print()

    z = zipfile.ZipFile(ipa)
    names = z.namelist()

    # A. dylib 存在
    dylibs = [n for n in names if n.endswith("Frameworks/KKCast.dylib")]
    if not dylibs:
        fail("包里没有 Frameworks/KKCast.dylib")
        print("\n结论：FAIL")
        return 1
    info = z.getinfo(dylibs[0])
    if info.file_size < 1024:
        fail(f"dylib 只有 {info.file_size} 字节，像是空壳")
    else:
        ok(f"dylib 存在，{info.file_size} 字节")

    # B. dylib 是合法 arm64
    db = z.read(dylibs[0])
    if u32(db, 0) != MH_MAGIC_64:
        fail(f"dylib magic=0x{u32(db,0):08x}，不是 MH_MAGIC_64")
    elif u32(db, 4) != CPU_TYPE_ARM64:
        fail(f"dylib cputype=0x{u32(db,4):08x}，不是 arm64")
    elif u32(db, 12) != 6:
        fail(f"dylib filetype={u32(db,12)}，不是 MH_DYLIB(6)")
    else:
        ok("dylib 是 arm64 MH_DYLIB")

    # 找可执行文件：用 Info.plist 的 CFBundleExecutable，别猜
    plists = [n for n in names if n.endswith(".app/Info.plist") and n.startswith("Payload/")]
    if not plists:
        fail("包里没有 Payload/*.app/Info.plist")
        print("\n结论：FAIL")
        return 1
    plist_name = plists[0]
    app_arc = plist_name[: -len("/Info.plist")]
    pdata = plistlib.loads(z.read(plist_name))
    exe_name = pdata.get("CFBundleExecutable")
    exe_arc = f"{app_arc}/{exe_name}"
    if exe_arc not in names:
        fail(f"找不到可执行文件 {exe_arc}")
        print("\n结论：FAIL")
        return 1

    blob = z.read(exe_arc)
    ok(f"可执行文件 {exe_arc}，{len(blob)} 字节")

    # C/D/G：遍历 load command
    if u32(blob, 0) != MH_MAGIC_64:
        fail(f"可执行文件 magic=0x{u32(blob,0):08x} 不对")
        print("\n结论：FAIL")
        return 1

    ncmds = u32(blob, 16)
    sizeofcmds = u32(blob, 20)
    off = 32
    found_dylib = False
    found_codesig = False
    linkedit = None
    platform = None

    for _ in range(ncmds):
        if off + 8 > len(blob):
            fail(f"load command 越界 @ {off}")
            break
        cmd = u32(blob, off)
        cs = u32(blob, off + 4)
        if cs < 8:
            fail(f"cmdsize 异常 {cs} @ {off}")
            break
        if cmd == LC_LOAD_DYLIB:
            noff = u32(blob, off + 8)
            nm = blob[off + noff:off + cs].split(b"\x00")[0].decode("utf-8", "replace")
            if "KKCast.dylib" in nm:
                found_dylib = True
                ok(f"LC_LOAD_DYLIB → {nm}")
        elif cmd == LC_CODE_SIGNATURE:
            found_codesig = True
        elif cmd == LC_SEGMENT_64:
            sname = blob[off + 8:off + 24].split(b"\x00")[0].decode("ascii", "replace")
            fileoff = u64(blob, off + 40)
            filesize = u64(blob, off + 48)
            if sname == "__LINKEDIT":
                linkedit = (fileoff, filesize)
        elif cmd == LC_BUILD_VERSION:
            platform = u32(blob, off + 8)
        off += cs

    if not found_dylib:
        fail("可执行文件里没有指向 KKCast.dylib 的 LC_LOAD_DYLIB —— 注入没生效")

    # D. 两个 Mach-O 都必须带合法 ad-hoc 签名。
    # 这一项是"装上就闪退"的唯一结构性解释，必须用 page hash 全量复核，
    # 不能只检查 LC_CODE_SIGNATURE 存在（存在但 hash 不符照样 abort）。
    if not found_codesig:
        fail("可执行文件没有 LC_CODE_SIGNATURE —— 裸 Mach-O 在 dyld 加载时 abort")
    else:
        signed_ok, signed_msg = adhoc_sign.verify_signature(blob)
        if signed_ok:
            ok(f"主程序 ad-hoc 签名有效（{signed_msg}）")
        else:
            fail(f"主程序签名无效：{signed_msg}")

    dblob = z.read(dylibs[0])
    # 注意：dylib 的 identifier 不是 bundle id，是 dylib 文件名
    dok, dmsg = adhoc_sign.verify_signature(dblob)
    if dok:
        ok(f"注入 dylib ad-hoc 签名有效（{dmsg}）")
    else:
        fail(f"注入 dylib 签名无效：{dmsg}")

    # D2. 独立复核 CodeDirectory 结构 —— 不经过 adhoc_sign 的 verify。
    #
    # 为什么需要这条：签名器和校验器是同一套字段偏移写的。如果偏移本身
    # 错了（v1 就是把 0x20400 的 header 当 44 字节），"自己验自己"永远
    # 通过，真机却整段错位 → 闪退。这条断言从 Mach-O 原始字节独立取值，
    # 用 version 反推 header 长度，两个数必须相等。
    def cd_struct_of(data, label):
        hits = [(o, cs) for o, cmd, cs in adhoc_sign.walk_cmds(data)
                if cmd == LC_CODE_SIGNATURE]
        if not hits:
            fail(f"{label}: 无 LC_CODE_SIGNATURE，跳过 CD 结构复核")
            return
        do = u32(data, hits[0][0] + 8)
        count = struct.unpack_from(">I", data, do + 8)[0]
        cdo = None
        for i in range(count):
            t, o_ = struct.unpack_from(">II", data, do + 12 + 8 * i)
            if t == 0:
                cdo = do + o_
                break
        if cdo is None:
            fail(f"{label}: SuperBlob 无 CodeDirectory")
            return
        version = struct.unpack_from(">I", data, cdo + 8)[0]
        ident_off = struct.unpack_from(">I", data, cdo + 20)[0]
        hash_off = struct.unpack_from(">I", data, cdo + 16)[0]
        cd_len = struct.unpack_from(">I", data, cdo + 4)[0]
        ncs = struct.unpack_from(">I", data, cdo + 28)[0]
        hs = data[cdo + 36]
        # 独立算出该 version 应有的 header 长（不复用 adhoc_sign 的函数）
        want = 44
        if version >= 0x20100:
            want += 4
        if version >= 0x20200:
            want += 4
        if version >= 0x20300:
            want += 12
        if version >= 0x20400:
            want += 24
        if version >= 0x20500:
            want += 8
        if ident_off != want:
            fail(f"{label}: version=0x{version:x} 要求 header {want} 字节，"
                 f"实际 identOffset={ident_off} —— CodeDirectory 结构错位，"
                 f"iOS 会把 identifier/hash 读成 execSeg 字段，签名必被拒")
        else:
            ok(f"{label}: CodeDirectory header {want} 字节与 version=0x{version:x} 匹配")
        if cd_len != hash_off + ncs * hs:
            fail(f"{label}: CD.length={cd_len} != hashOffset({hash_off})"
                 f"+nCodeSlots({ncs})*hashSize({hs})={hash_off + ncs * hs}")
        else:
            ok(f"{label}: CD.length 与 hash 表布局自洽（{cd_len}）")

    cd_struct_of(blob, "主程序")
    cd_struct_of(dblob, "dylib")

    # load command 链必须正好结束在 header 声明的位置
    expected_end = 32 + sizeofcmds
    if off != expected_end:
        fail(f"load command 链结束于 {off}，header 声明 {expected_end} —— 结构不自洽")
    else:
        ok(f"load command 链完整（ncmds={ncmds}, sizeofcmds=0x{sizeofcmds:x}）")

    if platform == 2:
        ok("可执行文件 platform=iOS")
    else:
        fail(f"可执行文件 platform={platform}，不是 iOS(2)")

    # G. __LINKEDIT 不能越界
    if linkedit:
        fend = linkedit[0] + linkedit[1]
        if fend > len(blob):
            fail(f"__LINKEDIT 结束于 {fend}，超过文件长度 {len(blob)} —— 截断出错")
        else:
            ok(f"__LINKEDIT 完整（结束于 {fend}，文件 {len(blob)}）")

    # E. Info.plist 本地网络权限
    desc = pdata.get("NSLocalNetworkUsageDescription")
    if desc and isinstance(desc, str) and desc.strip():
        ok(f"NSLocalNetworkUsageDescription: {desc}")
    else:
        fail("缺 NSLocalNetworkUsageDescription —— iOS 14+ 会静默拒绝局域网访问")

    # F. 旧签名目录
    sig = [n for n in names if "_CodeSignature/" in n]
    if sig:
        fail(f"残留 _CodeSignature {len(sig)} 个文件")
    else:
        ok("_CodeSignature 已清理")

    # H. Unix 权限位：可执行文件必须有 exec 位
    #
    # 这一项曾经被漏掉，代价是一次完整的错交付：`z.write()` 在 Windows
    # 上不保留 exec 位（NTFS 没有 Unix mode），所有条目都写成 0o666。
    # 表现是"装上了，点开闪退"，崩溃日志里没有任何跟权限有关的线索，
    # 极难定位。所以必须从 zip 的 external_attr 读，不能看本地文件属性。
    def mode_of(name):
        i = z.getinfo(name)
        return (i.external_attr >> 16) & 0xFFFF

    exe_arc = f"{app_arc}/{exe_name}"
    for must_exec in (exe_arc, dylibs[0]):
        if must_exec not in names:
            fail(f"缺文件: {must_exec}")
            continue
        m = mode_of(must_exec)
        if m & 0o111:
            ok(f"可执行位正确: {must_exec} ({oct(m)})")
        else:
            fail(f"{must_exec} 权限是 {oct(m)}，没有 exec 位 —— "
                 f"安装后点开必闪退（zip 重打包丢了 Unix mode）")

    # G. ★ 位移不变性：与原始未注入的主程序逐区比对
    #
    # 这一项是三轮真机闪退的最终判据，必须常驻门禁。
    # 前三轮修签名都没修对地方，就是因为缺这条：注入/签名可以在结构上
    # "看起来完全合法"（签名能验过、命令链自洽、段不越界），但仍把
    # __LINKEDIT 里的数据整体挪了位，而 dataoff 没跟着改。
    # dyld 在错位处读 chained fixups header，得到 imports_format=0
    # 之类的垃圾值，绑定阶段 abort —— 表现就是"看到启动画面就闪退"。
    #
    # 判据不是"文件长度对不对"（v1 的 del 让文件变短，看起来更合理），
    # 而是"该不变的字节必须逐字节相同、该变的字节只允许出现在签名区"。
    orig_path = os.path.join(HERE, "..", "..", "kkys_work", "movie.orig")
    orig_path = os.path.abspath(orig_path)
    if not os.path.isfile(orig_path):
        print("  ⏭️  找不到 movie.orig，跳过位移不变性比对（真机验证前必须补跑）")
    else:
        with open(orig_path, "rb") as f:
            ro = f.read()
        rn = z.read(exe_arc)
        mo, mn = inject_dylib.MachO(ro), inject_dylib.MachO(rn)

        # G1. chained fixups 必须原封不动
        def fixups_blob(raw, m):
            off = m.header_size
            for _ in range(m.ncmds):
                if inject_dylib.u32(raw, off) == 0x80000034:
                    do = inject_dylib.u32(raw, off + 8)
                    ds = inject_dylib.u32(raw, off + 12)
                    return do, ds, raw[do:do + ds], struct.unpack_from("<7I", raw, do)
                off += inject_dylib.u32(raw, off + 4)
            return None, None, None, None

        do1, ds1, b1, h1 = fixups_blob(ro, mo)
        do2, ds2, b2, h2 = fixups_blob(rn, mn)
        if do1 is None or do2 is None:
            fail("缺 LC_DYLD_CHAINED_FIXUPS，无法验位移")
        else:
            ok_off = (do1 == do2 and ds1 == ds2 and b1 == b2)
            if ok_off:
                ok(f"chained fixups 与原始样本逐字节一致（@0x{do2:x}，"
                   f"{ds2} 字节，count={h2[4]}, ifmt={h2[5]}）")
            else:
                fail(f"chained fixups 位移/内容变了：dataoff 0x{do1:x}→0x{do2:x}, "
                     f"size {ds1}→{ds2}, header {h1}→{h2} —— dyld 会读到错误绑定数据")
            if h2 and not (h2[0] == 0 and h2[5] in (1, 2, 3) and h2[4] > 0):
                fail(f"chained fixups header 非法: {h2} —— 绑定阶段必 abort")

        # G2. 数据段必须逐字节相同（这两段不承载 load command，也不承载签名）
        for seg_name in ("__DATA_CONST", "__DATA"):
            s1 = next((s for s in mo.segments if s["name"] == seg_name), None)
            s2 = next((s for s in mn.segments if s["name"] == seg_name), None)
            if not s1 or not s2:
                continue
            n = min(s1["filesize"], s2["filesize"])
            same = ro[s1["fileoff"]:s1["fileoff"] + n] == rn[s2["fileoff"]:s2["fileoff"] + n]
            if same and s1["fileoff"] == s2["fileoff"]:
                ok(f"{seg_name} 未位移（fileoff 0x{s2['fileoff']:x}，{n} 字节逐字节相同）")
            else:
                fail(f"{seg_name} 位移或内容变化（fileoff "
                     f"0x{s1['fileoff']:x}→0x{s2['fileoff']:x}）")

        # G3. 除签名区外，文件前段必须逐字节相同。
        #     差异只允许出现在三处：
        #       - header 里的 ncmds/sizeofcmds（16..24）
        #       - load command 区末尾（新命令写入的地方 + 被左移覆盖的旧签名命令）
        #       - 新签名区 [sig_do, EOF)
        #     其余任何位置出现差异 = 有数据被挪动，dyld 必崩。
        sig_cmd = [(o, inject_dylib.u32(rn, o)) for o in _walk_offsets(rn, mn)]
        sig_cmd = [o for o, cmd in sig_cmd if cmd == inject_dylib.LC_CODE_SIGNATURE]
        sig_do = inject_dylib.u32(rn, sig_cmd[0] + 8) if sig_cmd else len(rn)

        lc_end_o = mo.header_size + mo.sizeofcmds
        lc_end_n = mn.header_size + mn.sizeofcmds
        allow = set(range(16, 24))                       # ncmds / sizeofcmds
        allow |= set(range(lc_end_o - 16, lc_end_n))     # 命令区尾部
        allow |= set(range(sig_do, len(rn)))             # 签名区

        # __LINKEDIT 段头的 filesize 字段必须变：旧签名被截掉后，
        # 段声明要跟着收窄到新的文件末尾，否则 dyld 认为段尾还有 41KB
        # 数据而文件里没有，读到 EOF 外。这是"该变的字节"，不是位移。
        # 精确定位到该字段（段头 + 48..56），不整段放过。
        seg_allow = []
        for s in mn.segments:
            if s["name"] == "__LINKEDIT":
                seg_allow.append((s["cmd_off"] + 48, s["cmd_off"] + 56))
        for a, b in seg_allow:
            allow |= set(range(a, b))

        bad_at = None
        for i in range(min(len(ro), sig_do)):
            if ro[i] == rn[i] or i in allow:
                continue
            bad_at = i
            break
        if bad_at is None:
            ok(f"签名区之前的 {sig_do} 字节仅 header 计数、命令区、"
               f"__LINKEDIT.filesize 与签名区发生变化")
        else:
            fail(f"偏移 0x{bad_at:x} 处出现预期外的差异"
                 f"（{ro[bad_at]:#04x}→{rn[bad_at]:#04x}）—— 有数据被挪动")

    # G4. ★ dylib 的 chained fixups 也必须完好 —— 这条是 v2 的教训。
        #
        # v2 的主程序其实是好的（CF 逐字节一致），但 dylib 被"插入式签名"
        # 整体后移 16 字节，chained fixups header 从
        #   (0, 32, 104, 604, 125, 1, 0)
        # 变成
        #   (0, 0, 0, 0, 0, 32, 104)
        # 即 dyld 在声明 dataoff 处读到的是位移后的零/垃圾。
        # 只查主程序的话，v2 会全绿 —— 这正是"判据漏了一个受损方"。
        clean_dylib = os.path.join(HERE, "..", "dist-ci", "dist-dylib", "KKCast.dylib")
        clean_dylib = os.path.abspath(clean_dylib)
        if not os.path.isfile(clean_dylib):
            print("  ⏭️  找不到未签名的 KKCast.dylib，跳过 dylib 位移比对")
        elif dylibs:
            with open(clean_dylib, "rb") as f:
                dc = f.read()
            dn = z.read(dylibs[0])
            mc, mn_d = inject_dylib.MachO(dc), inject_dylib.MachO(dn)
            d1 = fixups_blob(dc, mc)
            d2 = fixups_blob(dn, mn_d)
            if d1[0] is None or d2[0] is None:
                fail("dylib 缺 LC_DYLD_CHAINED_FIXUPS")
            else:
                same_d = (d1[0] == d2[0] and d1[1] == d2[1] and d1[2] == d2[2])
                if same_d:
                    ok(f"dylib chained fixups 与未签名原件逐字节一致"
                       f"（@0x{d2[0]:x}，{d2[1]} 字节，count={d2[3][4]}, ifmt={d2[3][5]}）")
                else:
                    fail(f"dylib chained fixups 位移：dataoff 0x{d1[0]:x}→0x{d2[0]:x}, "
                         f"header {d1[3]}→{d2[3]} —— 注入 dylib 加载即崩")
                # dylib 的所有 dataoff 引用区也必须逐字节相同
                diffs_d = []
                lo = min(len(dc), len(dn))
                for i in range(lo):
                    if dc[i] != dn[i]:
                        diffs_d.append(i)
                # 允许：header 计数、命令区尾部、签名区
                lc_c = mc.header_size + mc.sizeofcmds
                lc_n = mn_d.header_size + mn_d.sizeofcmds
                sig_d = len(dn)
                for o, cmd, _cs in [(o, inject_dylib.u32(dn, o),
                                     inject_dylib.u32(dn, o + 4))
                                    for o in _walk_offsets(dn, mn_d)]:
                    if cmd == inject_dylib.LC_CODE_SIGNATURE:
                        sig_d = inject_dylib.u32(dn, o + 8)
                allow_d = set(range(16, 24)) | set(range(lc_c - 16, lc_n))
                allow_d |= set(range(sig_d, len(dn)))
                for s in mn_d.segments:
                    if s["name"] == "__LINKEDIT":
                        allow_d |= set(range(s["cmd_off"] + 48, s["cmd_off"] + 56))
                stray = [i for i in diffs_d if i not in allow_d]
                if not stray:
                    ok(f"dylib 签名区之前的 {sig_d} 字节无预期外差异")
                else:
                    fail(f"dylib 在 0x{stray[0]:x} 处出现预期外差异"
                         f"（{dc[stray[0]]:#04x}→{dn[stray[0]]:#04x}）—— 内容被挪动")

    # 首条必须是 Payload/，否则部分安装器（含老版 TrollStore）解包失败
    first = z.infolist()[0].filename
    if first == "Payload/":
        ok("首条目为 Payload/")
    else:
        fail(f"首条目是 {first}，应为 Payload/")

    # 附加：确认原有资源没被破坏（防止解包/重打包丢文件）
    must_keep = [
        f"{app_arc}/Assets.car",
        f"{app_arc}/PkgInfo",
        f"{app_arc}/embedded.mobileprovision",
    ]
    for m in must_keep:
        if m in names:
            ok(f"原有资源保留: {os.path.basename(m)}")
        else:
            fail(f"原有资源丢失: {m}")

    print()
    if FAIL:
        print(f"结论：FAIL（{len(FAIL)} 项）")
        return 1
    print("结论：PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())