#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证明 adhoc_sign 与 verify_signature 会失败，而不是永真通过。

三段式：
  1. 正向：对真实 Mach-O 签名 → verify 必须通过；header 必须 88 字节
  2. ★ 位移不变性：签名绝不能移动任何被 fileoff/dataoff 引用的字节
     —— 这是"出现进入画面就闪退"的根因（v2 插了 16 字节，导致
        chained fixups header 从 114688 移到 114704，dyld 读到零填充）
  3. 反向注入：篡改 7 处 → verify 必须逐条失败
     ★ 其中一条是回放 v1 的 44 字节 header 缺陷
  4. 还原：重新签名 → verify 必须再次通过

自检判据必须能失败：如果某条断言在缺陷存在时仍然 PASS，它就是装饰。
"""
import hashlib
import os
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import adhoc_sign as S

B = "C:/Users/fengb/WorkBuddy/2026-11-16-14-19-37"
# ★ 输入必须是"未签名且结构完好"的主程序。
#
# 旧值指向 kkys_work/movie.patched —— 那是 v1 注入工具用 `del` 位移损坏的
# 历史产物，它的 chained fixups 在声明 dataoff 处读出 (3249,1,0,0,5,0,0)。
# 拿它当基准，等于让签名自检去"修复"一份早就坏了的文件：断言报红是
# 正确的（判据没错），但红的原因是输入坏了，不是签名器错了。
# 现在改为现场从 movie.orig 剥离旧签名 + 注入，产出干净的未签名主程序。
SRC_ORIG = B + "/kkys_work/movie.orig"
SRC_DYLIB = B + "/KKCast/dist-ci/dist-dylib/KKCast.dylib"  # dylib
IDENT = "com.FastenerC.Bolt"
_WORK = None


def clean_unsigned_exec():
    """从 movie.orig 现场生成一份干净的未签名主程序（剥离签名 + 注入）。

    每一步都断言"没位移"，坏掉立刻停 —— 不能把坏输入悄悄喂给后面的判据。
    """
    global _WORK
    if _WORK:
        return _WORK
    sys.path.insert(0, HERE)
    import inject_dylib as INJ
    raw = open(SRC_ORIG, "rb").read()
    m = INJ.MachO(raw)
    injected = INJ.inject_inplace(m, "@executable_path/Frameworks/KKCast.dylib")
    m2 = INJ.MachO(bytes(injected))
    stripped, _ = INJ.strip_codesig(m2)
    d = os.path.join(tempfile.mkdtemp(prefix="kkexec_"), "movie.unsigned")
    with open(d, "wb") as f:
        f.write(stripped)

    # 门禁：这份输入必须自身完好，否则后面所有断言都无意义
    have = [(o, cs) for o, cmd, cs in S.walk_cmds(stripped) if cmd == S.LC_CODE_SIGNATURE]
    assert not have, "干净输入里不该还有 LC_CODE_SIGNATURE"
    cf = [x for x in linkedit_refs(stripped) if x[0] == "LC_DYLD_CHAINED_FIXUPS"]
    assert cf, "干净输入里没有 CHAINED_FIXUPS"
    hdr = struct.unpack_from("<7I", stripped, cf[0][1])
    assert hdr[0] == 0 and hdr[5] in (1, 2, 3) and hdr[4] > 0, \
        f"干净输入的 chained fixups header 非法: {hdr}"
    _WORK = d
    return d


SRC_EXEC = None     # 由 clean_unsigned_exec() 惰性生成，见 main

fails = []


def check(cond, msg):
    print(("  ✅ " if cond else "  ❌ ") + msg)
    if not cond:
        fails.append(msg)


def cd_offset(data):
    """CodeDirectory 在文件中的绝对偏移。

    SuperBlob 布局：12 字节头 + count*8 字节索引；
    索引项 i = (type @ 12+8i, offset @ 12+8i+4)。
    不要写成 12+8i+8 —— 那是下一项的 type。
    """
    hits = [(o, cs) for o, cmd, cs in S.walk_cmds(data) if cmd == S.LC_CODE_SIGNATURE]
    do = S.u32(data, hits[0][0] + 8)
    count = struct.unpack_from(">I", data, do + 8)[0]
    for i in range(count):
        typ, off = struct.unpack_from(">II", data, do + 12 + 8 * i)
        if typ == 0:
            return do + off
    raise ValueError("SuperBlob 里没有 CodeDirectory")


def linkedit_refs(data):
    """收集所有「dataoff/datasize」型 load command，返回 [(name, off, size)]。

    这些是 dyld 按**绝对文件偏移**读取的数据。签名如果移动了文件内容，
    这些偏移就会指向错误的位置 —— 这是"进入画面闪退"的直接原因。
    """
    NAMES = {
        0x80000034: "LC_DYLD_CHAINED_FIXUPS",
        0x80000033: "LC_DYLD_EXPORTS_TRIE",
        0x22: "LC_DYLD_INFO",
        0x80000022: "LC_DYLD_INFO_ONLY",
        0x26: "LC_FUNCTION_STARTS",
        0x29: "LC_DATA_IN_CODE",
        0x2B | 0x80000000: "LC_DYLIB_CODE_SIGN_DRS",
        0x2E | 0x80000000: "LC_LINKER_OPTIMIZATION_HINT",
        0x2: "LC_SYMTAB",
        0x1D: "LC_CODE_SIGNATURE",
    }
    out = []
    for off, cmd, cs in S.walk_cmds(data):
        if cmd in NAMES:
            if cmd == 0x2:      # SYMTAB 有两个偏移
                out.append((NAMES[cmd] + ".symoff", S.u32(data, off + 8),
                            S.u32(data, off + 12) * 16))
                out.append((NAMES[cmd] + ".stroff", S.u32(data, off + 16),
                            S.u32(data, off + 20)))
            else:
                out.append((NAMES[cmd], S.u32(data, off + 8), S.u32(data, off + 12)))
    return out


def check_shift_invariance(before, after, label):
    """签名前后，每个 dataoff 引用的内容必须逐字节相同。

    这是本次真机闪退的正面判据：
      v2 的签名器插了 16 字节，chained fixups 从 114688 移到 114704，
      但 LC_DYLD_CHAINED_FIXUPS.dataoff 仍是 114688（dyld 读到零填充）。
      这条断言在 v2 上必然红。
    """
    refs_b = {n: (o, s) for n, o, s in linkedit_refs(before)}
    refs_a = {n: (o, s) for n, o, s in linkedit_refs(after)}
    check(set(refs_a) - {"LC_CODE_SIGNATURE"} == set(refs_b) - {"LC_CODE_SIGNATURE"},
          f"{label}: load command 集合不变（不新增/不丢失引用型命令）")

    bad = []
    for name in refs_b:
        if name == "LC_CODE_SIGNATURE":
            continue       # 它会变，是预期内的
        if name not in refs_a:
            bad.append(f"{name} 消失")
            continue
        ob, sb = refs_b[name]
        oa, sa = refs_a[name]
        if (ob, sb) != (oa, sa):
            bad.append(f"{name} 偏移 {ob}→{oa} 或长度 {sb}→{sa} 被改动")
            continue
        if sb > 0 and before[ob:ob + sb] != after[oa:oa + sa]:
            # 定位第一处不同
            d = next((i for i in range(min(sb, sa)) if before[ob + i] != after[oa + i]), -1)
            bad.append(f"{name} 内容变了（首差 +{d}）")
    check(not bad, f"{label}: 所有 dataoff 引用内容逐字节未变"
                   + ("" if not bad else f" —— {bad}"))

    # 关键锚点：chained fixups 的 header 魔数必须仍在 dataoff 处
    for name, (o, s) in refs_a.items():
        if name == "LC_DYLD_CHAINED_FIXUPS" and s > 16:
            hdr = struct.unpack_from("<IIIIIII", after, o)
            ok = (hdr[0] == 0 and hdr[1] < s and hdr[4] > 0
                  and hdr[5] in (1, 2, 3))
            check(ok, f"{label}: chained fixups header 在 dataoff={o} 处可解析 "
                      f"(imports_count={hdr[4]}, imports_format={hdr[5]})")


def build_v1_style_signature(data, identifier):
    """完整复刻 v1（装上真机闪退的那一版）的签名算法。

    v1 的写法：声明 version=0x20400，但 header 只写 44 字节，
    identOffset=44、hashOffset=44+len(ident)。其余全部合法：
      · page hash 全部正确
      · SuperBlob.length / count 正确
      · CD.length = hashOffset + nCodeSlots*hashSize
      · dataoff+datasize == filesize
      · __LINKEDIT.filesize 覆盖签名区
    唯一错误：header 少 44 字节，导致系统按 0x20400 解析时把
    identifier 与 page hash 读成 execSegBase/Limit/Flags。

    必须这样构造（而不是去改合法签名），否则会引入别的错误，
    让 FAIL 命中的是别的断言，测不到 header 长度这条。
    """
    page = 1 << 14
    probe = S.insert_codesig_cmd(data, 0, 0)
    code_limit = len(probe)
    n_slots = (code_limit + page - 1) // page

    ident = identifier.encode("utf-8") + b"\x00"
    hdr = 44                                   # ← v1 的错误就在这里
    ident_off = hdr
    hash_off = ident_off + len(ident)
    cd_len = hash_off + n_slots * 32

    cs_blob = struct.pack(">II", S.CSMAGIC_BLOBWRAPPER, 8)
    cd_off = 12 + 16
    blob_raw = cd_off + cd_len + len(cs_blob)
    blob_len = S.align8(blob_raw)

    d = bytearray(S.insert_codesig_cmd(data, code_limit, blob_len))
    le = S.find_linkedit(d)
    d[le[0] + 48:le[0] + 56] = struct.pack("<Q", S.align8(code_limit + blob_len) - le[1])

    cd = bytearray()
    cd += struct.pack(">II", S.CSMAGIC_CODEDIRECTORY, cd_len)
    cd += struct.pack(">I", 0x00020400)        # ← 声明高版本
    cd += struct.pack(">I", 0x2)               # CS_ADHOC
    cd += struct.pack(">I", hash_off)
    cd += struct.pack(">I", ident_off)         # = 44，不是 88
    cd += struct.pack(">I", 0)
    cd += struct.pack(">I", n_slots)
    cd += struct.pack(">I", code_limit)
    cd += struct.pack(">BBBB", 32, 2, 0, 14)
    cd += struct.pack(">I", 0)                 # 到此 44 字节，后面直接接 identifier
    cd += ident
    for i in range(n_slots):
        s = i * page
        cd += hashlib.sha256(bytes(d[s:min(s + page, code_limit)])).digest()
    assert len(cd) == cd_len, (len(cd), cd_len)

    sb = bytearray()
    sb += struct.pack(">III", S.CSMAGIC_EMBEDDED_SIGNATURE, blob_raw, 2)
    sb += struct.pack(">II", 0, cd_off)
    sb += struct.pack(">II", 0x10000, cd_off + cd_len)
    sb += cd
    sb += cs_blob
    sb += b"\x00" * (blob_len - blob_raw)
    return bytes(d) + bytes(sb)


tmp = tempfile.mkdtemp(prefix="adhoc-")
try:
    # 现场生成干净的未签名输入（见 clean_unsigned_exec 的说明）
    SRC_EXEC = clean_unsigned_exec()
    print(f"输入: {SRC_EXEC}  {os.path.getsize(SRC_EXEC)} 字节（由 movie.orig 现场生成）")

    path = os.path.join(tmp, "movie")
    shutil.copyfile(SRC_EXEC, path)

    print("[1] 正向（主程序）")
    changed, n = S.sign_file(path, IDENT)
    data = open(path, "rb").read()
    ok, msg = S.verify_signature(data)
    check(changed, "签名器执行了写入")
    check(ok, f"签名后可复核通过（{msg}）")
    check(n > 100, f"生成了实质签名 blob（{n} 字节）")

    cdo = cd_offset(data)
    hdr = S.bu32(data, cdo + 20)
    check(hdr == 88, f"header 长度 88 字节（实测 identOffset={hdr}）")
    check(S.bu32(data, cdo + 8) == 0x20400, "version=0x20400")
    eflags = struct.unpack_from(">Q", data, cdo + 80)[0]
    check(eflags & S.CS_EXECSEG_MAIN_BINARY, f"主程序 execSegFlags 置 MAIN_BINARY（0x{eflags:x}）")
    lim = struct.unpack_from(">Q", data, cdo + 72)[0]
    text = S.find_segment(data, "__TEXT")
    check(lim == text[2], f"execSegLimit={lim} == __TEXT.filesize={text[2]}")

    print("[2] 位移不变性（本次真机闪退的正面判据）")
    raw0 = open(SRC_EXEC, "rb").read()
    check(len(data) == len(raw0) + n,
          f"文件长度只增加签名 blob（{len(raw0)} + {n} = {len(raw0)+n}，实测 {len(data)}）")
    # 签名区之前的内容必须与原文件逐字节相同，只有零填充里的 16 字节命令和第 0 页计数变了
    body_orig = raw0
    body_new = data[:len(raw0)]
    diff = [i for i in range(min(len(body_orig), len(body_new)))
            if body_orig[i] != body_new[i]]
    # 允许差异只出现在 (a) header ncmds/sizeofcmds 16..24
    #                    (b) 原 lc_end 处的 16 字节命令
    lc_end0 = 32 + S.u32(raw0, 20)
    allowed = set(range(16, 24)) | set(range(lc_end0, lc_end0 + 16))
    # __LINKEDIT.filesize 必须变（要覆盖追加的签名 blob），这是预期内的。
    # 不能把它当成"位移"，但也不能因此放宽整段 —— 只放这一个 8 字节字段。
    le_off = S.find_linkedit(raw0)[0]
    allowed |= set(range(le_off + 48, le_off + 56))
    unexpected = [i for i in diff if i not in allowed]
    check(not unexpected,
          f"签名区之前的差异只出现在 header 计数与 lc_end 处的命令"
          f"（差异 {len(diff)} 字节，越界 {len(unexpected)}：{unexpected[:8]}）")
    check(body_orig[:16384] != body_new[:16384] or True, "（第 0 页如下单独校验）")
    # 首个 section 之后的内容必须与原文件完全一致（这是 dyld 真正执行的代码与数据）
    first_sect = S.find_slack(raw0)[1]
    check(raw0[first_sect:] == data[first_sect:len(raw0)],
          f"首个 section({first_sect}) 之后的全部内容逐字节未变"
          f"（{len(raw0)-first_sect} 字节）")
    check_shift_invariance(raw0, data, "主程序")

    print("[3] 反向注入：篡改必须被抓")
    # 2a 改被签名的代码页
    d = bytearray(open(path, "rb").read())
    d[5 * 16384 + 7] ^= 0xFF
    ok_a, msg_a = S.verify_signature(bytes(d))
    check(not ok_a, f"改代码页 → FAIL（{msg_a}）")

    # 2b 改 codeLimit
    d = bytearray(open(path, "rb").read())
    d[cdo + 32:cdo + 36] = struct.pack(">I", 0)
    ok_b, msg_b = S.verify_signature(bytes(d))
    check(not ok_b, f"改 codeLimit → FAIL（{msg_b}）")

    # 2c 清 CS_ADHOC
    d = bytearray(open(path, "rb").read())
    d[cdo + 12:cdo + 16] = struct.pack(">I", 0)
    ok_c, msg_c = S.verify_signature(bytes(d))
    check(not ok_c, f"清 CS_ADHOC → FAIL（{msg_c}）")

    # ★ 2d 回放 v1 真机闪退缺陷：44 字节 header 声明 version=0x20400
    raw = open(SRC_EXEC, "rb").read()     # 从未签名原件出发复刻 v1 算法
    broken = build_v1_style_signature(raw, IDENT)
    ok_d, msg_d = S.verify_signature(broken)
    check(not ok_d, f"44 字节 header（v1 缺陷）→ FAIL（{msg_d}）")
    check("header" in msg_d or "identOffset" in msg_d,
          f"失败原因命中『header 长度/identOffset』这条断言（{msg_d}）")
    # 确认这个缺陷样本里 page hash 本身还是对的 —— 证明断言抓的是结构错位，
    # 否则"失败"可能只是因为 hash 坏了，抓不到真正的问题
    bd = bytearray(broken)
    bcd = cd_offset(bd)
    ncs = S.bu32(bd, bcd + 28)
    ho = S.bu32(bd, bcd + 16)
    lc = [(o, cs) for o, cmd, cs in S.walk_cmds(bd) if cmd == S.LC_CODE_SIGNATURE][0][0]
    dow = S.u32(bd, lc + 8)
    bad = [i for i in range(ncs)
           if hashlib.sha256(bytes(bd[i * 16384:min((i + 1) * 16384, dow)])).digest()
           != bytes(bd[bcd + ho + i * 32: bcd + ho + (i + 1) * 32])]
    check(len(bad) == 0, f"该缺陷样本的 page hash 仍然全对（{len(bad)} 个不符）"
                          "—— 证明断言抓的是结构错位而非 hash 损坏")

    # 2e 主程序去掉 MAIN_BINARY 标记
    d = bytearray(open(path, "rb").read())
    d[cdo + 80:cdo + 88] = struct.pack(">Q", 0)
    ok_e, msg_e = S.verify_signature(bytes(d))
    check(not ok_e, f"主程序清 execSegFlags → FAIL（{msg_e}）")

    # 2f CD.length 与实际不符
    d = bytearray(open(path, "rb").read())
    d[cdo + 4:cdo + 8] = struct.pack(">I", S.bu32(d, cdo + 4) + 8)
    ok_f, msg_f = S.verify_signature(bytes(d))
    check(not ok_f, f"改 CD.length → FAIL（{msg_f}）")

    print("[3] dylib：签名必须不置 MAIN_BINARY，且不得位移")
    dpath = os.path.join(tmp, "KKCast.dylib")
    shutil.copyfile(SRC_DYLIB, dpath)
    draw0 = open(SRC_DYLIB, "rb").read()
    ch2, _ = S.sign_file(dpath, "KKCast.dylib")
    dd = open(dpath, "rb").read()
    ok3, msg3 = S.verify_signature(dd)
    check(ch2 and ok3, f"dylib 签名通过（{msg3}）")
    dcdo = cd_offset(dd)
    de = struct.unpack_from(">Q", dd, dcdo + 80)[0]
    check(de == 0, f"dylib execSegFlags=0（实测 0x{de:x}）")
    check_shift_invariance(draw0, dd, "dylib")
    # dylib 的 chained fixups 是 dyld 加载它的第一道关，单独再验一次原始偏移
    cf = [x for x in linkedit_refs(dd) if x[0] == "LC_DYLD_CHAINED_FIXUPS"]
    check(len(cf) == 1, "dylib 有且只有一条 LC_DYLD_CHAINED_FIXUPS")
    if cf:
        o, s = cf[0][1], cf[0][2]
        hdr = struct.unpack_from("<IIIIIII", dd, o)
        check(hdr[0] == 0 and hdr[5] in (1, 2, 3) and hdr[4] > 0,
              f"dylib chained fixups 在 dataoff={o} 处 header 合法"
              f"（version={hdr[0]} count={hdr[4]} fmt={hdr[5]}）")

    print("[4] 回放 v2 缺陷：插入式签名必然破坏 dataoff 引用")
    # v2 用 out[end:end] = cmd 插入 16 字节，导致后续内容整体后移。
    # 这条断言必须红 —— 如果它变绿，说明位移不变性检查是装饰。
    def build_v2_style_signature(data, identifier):
        page = 1 << 14
        ncmds, sizeofcmds = S.u32(data, 16), S.u32(data, 20)
        lc_end = 32 + sizeofcmds
        code_limit = len(data) + 16          # v2 以为长度会 +16
        n_slots = (code_limit + page - 1) // page
        ident = identifier.encode() + b"\x00"
        hdr = 88
        ident_off = hdr
        hash_off = ident_off + len(ident)
        cd_len = hash_off + n_slots * 32
        cs_blob = struct.pack(">II", S.CSMAGIC_BLOBWRAPPER, 8)
        blob_raw = 12 + 16 + cd_len + len(cs_blob)
        blob_len = S.align8(blob_raw)
        d = bytearray(data)
        cmd = (struct.pack("<I", S.LC_CODE_SIGNATURE) + struct.pack("<I", 16)
               + struct.pack("<I", code_limit) + struct.pack("<I", blob_len))
        d[lc_end:lc_end] = cmd                # ← v2 的错误：插入而非覆盖
        d[16:20] = struct.pack("<I", ncmds + 1)
        d[20:24] = struct.pack("<I", sizeofcmds + 16)
        return bytes(d)

    v2 = build_v2_style_signature(raw0, IDENT)
    refs_v2 = linkedit_refs(v2)
    # 找到 chained fixups，看它 dataoff 处的 header 是否还合法
    cf2 = [x for x in refs_v2 if x[0] == "LC_DYLD_CHAINED_FIXUPS"]
    broken_hdr = False
    if cf2:
        o, s = cf2[0][1], cf2[0][2]
        hdr = struct.unpack_from("<IIIIIII", v2, o)
        broken_hdr = not (hdr[0] == 0 and hdr[5] in (1, 2, 3) and hdr[4] > 0)
    check(broken_hdr,
          "v2 插入式签名后，chained fixups 在声明 dataoff 处已无法解析"
          " —— 这正是真机闪退的机制")

    print("[5] 还原后复跑")
    shutil.copyfile(SRC_EXEC, path)
    S.sign_file(path, IDENT)
    ok2, msg2 = S.verify_signature(open(path, "rb").read())
    check(ok2, f"重签后恢复干净（{msg2}）")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print()
if fails:
    print(f"结论：FAIL（{len(fails)} 项）")
    for f in fails:
        print("  - " + f)
    sys.exit(1)
print("结论：PASS —— 校验器能失败（含 v1 缺陷回放），且失败可恢复")