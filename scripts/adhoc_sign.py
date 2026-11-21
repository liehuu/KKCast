#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给单个 Mach-O 做 ad-hoc（ldid -S 等价）签名，纯 Python，无 macOS 工具依赖。

为什么需要这个：
  TrollStore 绕过的是安装期的证书链校验，但 dyld 加载每个 image 时仍会
  校验 cdhash。注入 dylib 和被 patch 的主程序如果完全没有签名，装上去
  点开就 abort。build_ipa.py 里"TrollStore 会自动签"的假设是错的：
  TrollStore 只对**已 fakesign 过**的二进制保留 entitlements 并重签，
  对裸 Mach-O 不会凭空造签名槽。

格式来源（不是猜的）：
  用 kkys_work/movie.orig 的真实 Apple 签名反推：
    version=0x20400, hashType=2(SHA256), hashSize=32, pageSize=2^14,
    identifier=com.FastenerC.Bolt, nCodeSlots=ceil(codeLimit/16384)
  并用 SHA-256 重算原包 697 个 page hash，697/697 全部吻合，
  证明 hash 覆盖范围和分块方式正确。

  ★ v2 修正（v1 装到真机仍闪退的根因）：
    CodeDirectory 的 header 长度**由 version 决定，不是固定 44 字节**。
    version=0x20400 时 header 是 88 字节：
      44..47  scatterOffset
      48..51  teamOffset
      52..55  spare3
      56..63  codeLimit64
      64..71  execSegBase
      72..79  execSegLimit
      80..87  execSegFlags
    v1 只写 44 字节 header 却声明 version=0x20400，系统按 88 字节解析时
    把 identifier 和 page hash 当成了 execSegBase/Limit/Flags（读出来是
    0xfcaeb546fb87752c 这类垃圾），签名结构整体错位 → 校验失败 → 闪退。
    v1 的验证器也按 44 读，所以"自己验自己"永远通过。现已按 version 解析。

与 Apple 正式签名的差别（这正是 ldid -S 的做法）：
  · flags 置 CS_ADHOC(0x2)，不提供 CMS 签名者（无证书链）
  · 只保留 CodeDirectory blob + 一个空的 CodeSignature(0xfade0b01, len=8)
  · nSpecialSlots=0：不带 Requirements/Entitlements/ResourceDir
    （原包 entitlements 仅 application-identifier / team-identifier /
      beta-reports-active / get-task-allow，无任何运行时权限，
      且 iOS 上网不需要 entitlement —— 丢掉不影响网络功能）
"""

import hashlib
import struct

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CS_ADHOC = 0x2

# execSegFlags
CS_EXECSEG_MAIN_BINARY = 0x1

LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_64 = 0x19

MH_EXECUTE = 2
MH_DYLIB = 6

PAGE_SIZE_LOG2 = 14
PAGE_SIZE = 1 << PAGE_SIZE_LOG2
HASH_SIZE = 32
HASH_TYPE_SHA256 = 2
CD_VERSION = 0x00020400


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def bu32(b, o):
    """CodeDirectory / SuperBlob 是大端，Mach-O load command 是小端。"""
    return struct.unpack_from(">I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def p32(v):
    return struct.pack("<I", v)


def p64(v):
    return struct.pack("<Q", v)


def align8(n):
    return (n + 7) & ~7


def cd_header_len(version):
    """CodeDirectory 固定头长度 —— 完全由 version 决定。

    这是 v1 的致命错误来源：写死 44 会让 0x20400 的结构整体错位。
    """
    n = 44
    if version >= 0x20100:
        n += 4              # scatterOffset
    if version >= 0x20200:
        n += 4              # teamOffset
    if version >= 0x20300:
        n += 4 + 8          # spare3 + codeLimit64
    if version >= 0x20400:
        n += 8 + 8 + 8      # execSegBase + execSegLimit + execSegFlags
    if version >= 0x20500:
        n += 4 + 4          # runtime + preEncryptOffset
    return n


def walk_cmds(data):
    """产出 (offset, cmd, cmdsize)。"""
    if len(data) < 32 or u32(data, 0) != 0xFEEDFACF:
        raise ValueError("不是 MH_MAGIC_64")
    ncmds = u32(data, 16)
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(data):
            raise ValueError("load command 越界")
        cs = u32(data, off + 4)
        if cs < 8:
            raise ValueError(f"cmdsize 非法 {cs} @ {off}")
        yield off, u32(data, off), cs
        off += cs


def find_segment(data, want):
    for off, cmd, cs in walk_cmds(data):
        if cmd == LC_SEGMENT_64:
            name = bytes(data[off + 8:off + 24]).split(b"\x00")[0].decode("ascii", "replace")
            if name == want:
                return off, u64(data, off + 40), u64(data, off + 48)
    return None


def find_linkedit(data):
    r = find_segment(data, "__LINKEDIT")
    if not r:
        raise ValueError("找不到 __LINKEDIT")
    return r


def macho_filetype(data):
    return u32(data, 12)


def find_slack(data):
    """返回 (lc_end, first_section_abs, slack_len)。

    load command 链结束处到 __TEXT 首个有内容 section 之间的零填充区。
    这就是 LC_CODE_SIGNATURE 必须写进去的位置 —— 写在这里不移动任何字节。
    """
    ncmds, sizeofcmds = u32(data, 16), u32(data, 20)
    lc_end = 32 + sizeofcmds
    first = None
    for off, cmd, cs in walk_cmds(data):
        if cmd == LC_SEGMENT_64:
            name = bytes(data[off + 8:off + 24]).split(b"\x00")[0].decode("ascii", "replace")
            if name == "__TEXT":
                fileoff = u64(data, off + 40)
                nsects = u32(data, off + 64)
                best = None
                p = off + 72
                for _ in range(nsects):
                    sec_off = u32(data, p + 48)
                    sec_size = u64(data, p + 40)
                    if sec_size > 0 and (best is None or sec_off < best):
                        best = sec_off
                    p += 80
                if best is not None:
                    first = fileoff + best
                break
    if first is None:
        raise ValueError("找不到 __TEXT 首个 section")
    return lc_end, first, first - lc_end


def insert_codesig_cmd(data, dataoff, datasize):
    """把 LC_CODE_SIGNATURE 写进 load command 链之后的**零填充区**。

    ★ v2 的错误（真机"出现进入画面就闪退"的根因）：
      旧实现用 `out[end:end] = cmd` **插入** 16 字节，把 lc_end 之后的
      所有字节整体后移 16。但段的 fileoff 和 load command 里的 dataoff
      （LC_DYLD_CHAINED_FIXUPS / SYMTAB / EXPORTS_TRIE / FUNCTION_STARTS）
      全部没改 —— dyld 于是去原偏移读，读到的是被前移后的错位内容。
      实测 dylib：chained fixups 从 114688 移到 114704，dyld 在
      114688 读到 20 字节零，解析出 imports_format=32 / imports_count=0，
      绑定阶段直接 abort。表现就是"看到 Launcher 进入画面，随即闪退"。
      主程序同理，只是它的 fixups 区靠后，被错位后同样炸。

    ★ 正确做法（ldid 也是这么做的）：
      写进 lc_end 起始的零填充，**文件长度完全不变**，所有 fileoff/
      dataoff 继续有效。只需要 ncmds/sizeofcmds 各加 16，这会改动第 0 页，
      所以必须在算 page hash 之前完成。

    为什么不担心覆盖有用数据：
      slack = __TEXT 首个 section 的绝对偏移 - lc_end。链接器保证这段是
      零填充（对齐用），它不属于任何 section。下面还断言了这 16 字节
      确实全零，不是零就拒绝执行 —— 宁可报错也不能悄悄破坏代码。
    """
    ncmds = u32(data, 16)
    sizeofcmds = u32(data, 20)
    lc_end, first_sect, slack = find_slack(data)

    if slack < 16:
        raise ValueError(
            f"load command 后只剩 {slack} 字节零填充，放不下 16 字节 "
            f"LC_CODE_SIGNATURE。此文件需要先把 __TEXT 整体后移一页"
            f"（重算所有 fileoff），本签名器不做这件事。")

    region = bytes(data[lc_end:lc_end + 16])
    if set(region) != {0}:
        raise ValueError(
            f"load command 后 16 字节不是零填充（{region.hex()}），"
            f"写入会覆盖真实节内容，拒绝执行")

    cmd = p32(LC_CODE_SIGNATURE) + p32(16) + p32(dataoff) + p32(datasize)
    out = bytearray(data)
    out[lc_end:lc_end + 16] = cmd            # 覆盖零填充，长度不变
    out[16:20] = p32(ncmds + 1)
    out[20:24] = p32(sizeofcmds + 16)
    assert len(out) == len(data), (len(out), len(data))
    return bytes(out)


def build_signature(data, identifier, exec_seg=None):
    """构造签名 blob 并追加到 data 末尾，返回 (新 bytes, blob 长度)。

    顺序很关键（改一处顺序，第 0 页 hash 就全错，装上去照样闪退）：
      1. 把 LC_CODE_SIGNATURE **写进零填充**（长度不变）+ 更新 ncmds/sizeofcmds
      2. codeLimit = 文件当前长度（签名 blob 从文件末尾开始，不参与自身 hash）
      3. 对每个 16384 字节 page 做 SHA-256
      4. CodeDirectory: version=0x20400 / **88 字节 header** / flags=CS_ADHOC
         hashSize=32 / hashType=2 / nSpecialSlots=0 / nCodeSlots / pageSize=14
      5. SuperBlob 索引 CodeDirectory(0) 与 CodeSignature(0x10000)
      6. 更新 __LINKEDIT.filesize，使其覆盖追加的签名 blob

    exec_seg: (base, limit, flags) 三元组；None 时按 filetype 自动定：
      主程序 → (0, __TEXT.filesize, CS_EXECSEG_MAIN_BINARY)
      dylib  → (0, 0, 0)
    """
    # ★ codeLimit = 原长度。新的 insert 不改变文件长度，
    # 所以这里不能用"插入后长度"（那会让 codeLimit 比实际大 16）。
    code_limit = len(data)
    n_slots = (code_limit + PAGE_SIZE - 1) // PAGE_SIZE

    if exec_seg is None:
        ft = macho_filetype(data)
        if ft == MH_EXECUTE:
            text = find_segment(data, "__TEXT")
            exec_seg = (0, text[2] if text else 0, CS_EXECSEG_MAIN_BINARY)
        else:
            exec_seg = (0, 0, 0)

    ident = identifier.encode("utf-8") + b"\x00"
    hdr_len = cd_header_len(CD_VERSION)
    ident_off = hdr_len
    hash_off = ident_off + len(ident)
    cd_len = hash_off + n_slots * HASH_SIZE

    cs_blob = struct.pack(">II", CSMAGIC_BLOBWRAPPER, 8)
    idx_off = 12
    cd_off = idx_off + 2 * 8
    blob_raw = cd_off + cd_len + len(cs_blob)
    blob_len = align8(blob_raw)          # 签名 blob 必须 8 字节对齐（原包 41504 也是）

    # 用真实 dataoff 把命令写进零填充（长度不变）
    before_len = len(data)
    data = bytearray(insert_codesig_cmd(data, code_limit, blob_len))
    assert len(data) == before_len == code_limit, (len(data), before_len, code_limit)

    # 关键顺序：__LINKEDIT 的 load command 位于第 0 页，
    # 它的 filesize 必须在算 page hash **之前**改成最终值。
    le_off, le_fo, le_fs = find_linkedit(data)
    final_total = code_limit + blob_len
    data[le_off + 48:le_off + 56] = p64(align8(final_total) - le_fo)

    # CodeDirectory：88 字节 header，逐字段写满（不是只写 44）
    #  0 magic | 4 length | 8 version | 12 flags
    #  16 hashOffset | 20 identOffset
    #  24 nSpecialSlots | 28 nCodeSlots | 32 codeLimit
    #  36 hashSize | 37 hashType | 38 platform | 39 pageSize | 40 spare2
    #  44 scatterOffset | 48 teamOffset | 52 spare3 | 56 codeLimit64
    #  64 execSegBase | 72 execSegLimit | 80 execSegFlags
    cd = bytearray()
    cd += struct.pack(">II", CSMAGIC_CODEDIRECTORY, cd_len)     # 0..7
    cd += struct.pack(">I", CD_VERSION)                          # 8
    cd += struct.pack(">I", CS_ADHOC)                            # 12
    cd += struct.pack(">I", hash_off)                            # 16
    cd += struct.pack(">I", ident_off)                           # 20
    cd += struct.pack(">I", 0)                                   # 24 nSpecialSlots
    cd += struct.pack(">I", n_slots)                             # 28 nCodeSlots
    cd += struct.pack(">I", code_limit)                          # 32 codeLimit
    cd += struct.pack(">BBBB", HASH_SIZE, HASH_TYPE_SHA256, 0, PAGE_SIZE_LOG2)  # 36..39
    cd += struct.pack(">I", 0)                                   # 40 spare2
    cd += struct.pack(">I", 0)                                   # 44 scatterOffset
    cd += struct.pack(">I", 0)                                   # 48 teamOffset（ad-hoc 无 team）
    cd += struct.pack(">I", 0)                                   # 52 spare3
    cd += struct.pack(">Q", 0)                                   # 56 codeLimit64（<4GB 不用）
    cd += struct.pack(">Q", exec_seg[0] & 0xFFFFFFFFFFFFFFFF)    # 64 execSegBase
    cd += struct.pack(">Q", exec_seg[1] & 0xFFFFFFFFFFFFFFFF)    # 72 execSegLimit
    cd += struct.pack(">Q", exec_seg[2] & 0xFFFFFFFFFFFFFFFF)    # 80 execSegFlags
    assert len(cd) == hdr_len, (len(cd), hdr_len)                # header 必须恰好 88
    cd += ident
    for i in range(n_slots):
        s = i * PAGE_SIZE
        e = min(s + PAGE_SIZE, code_limit)
        cd += hashlib.sha256(data[s:e]).digest()
    assert len(cd) == cd_len, (len(cd), cd_len)

    # SuperBlob.length 是真实内容长度；dataoff/datasize 覆盖到 8 字节对齐尾
    sb = bytearray()
    sb += struct.pack(">III", CSMAGIC_EMBEDDED_SIGNATURE, blob_raw, 2)
    sb += struct.pack(">II", 0, cd_off)        # CodeDirectory slot
    sb += struct.pack(">II", 0x10000, cd_off + cd_len)  # CodeSignature slot
    sb += cd
    sb += cs_blob
    sb += b"\x00" * (blob_len - blob_raw)
    assert len(sb) == blob_len, (len(sb), blob_len)

    out = bytearray(data)
    out += sb
    # LE.filesize 已在算 hash 前更新；此处绝不能再改，否则第 0 页 hash 失效
    return bytes(out), len(sb)


def sign_file(path, identifier, exec_seg=None):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 32:
        raise ValueError("文件太小")
    # 幂等：已经有签名就跳过，避免二次追加把 codeLimit 算进旧签名
    for _, cmd, _ in walk_cmds(data):
        if cmd == LC_CODE_SIGNATURE:
            return False, len(data)
    out, blob_len = build_signature(data, identifier, exec_seg)
    with open(path, "wb") as f:
        f.write(out)
    return True, blob_len


def verify_signature(data, verbose=False):
    """独立复核签名：结构合法 + 重新计算全部 page hash。返回 (ok, 描述)。

    关键判据：header 长度必须等于 version 对应的值，identOffset 必须等于它。
    这条断言正是 v1 骗过自己的那一条 —— v1 只写 44 却不检查。
    """
    hits = [(o, cs) for o, cmd, cs in walk_cmds(data) if cmd == LC_CODE_SIGNATURE]
    if len(hits) != 1:
        return False, f"LC_CODE_SIGNATURE 数量 {len(hits)}，应为 1"
    cmd_off, cmd_sz = hits[0]
    do, ds = u32(data, cmd_off + 8), u32(data, cmd_off + 12)
    if do + ds != len(data):
        return False, f"签名区 dataoff+ds={do+ds} != filesize={len(data)}"
    blob = data[do:do + ds]
    magic, length, count = struct.unpack_from(">III", blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE or count != 2 or length > ds or length + 8 < ds:
        return False, f"SuperBlob magic={magic:08x} length={length} ds={ds} count={count}"

    entries = [struct.unpack_from(">II", blob, 12 + 8 * i) for i in range(count)]
    cd_idx = [e for e in entries if e[0] == 0]
    if len(cd_idx) != 1:
        return False, "SuperBlob 里没有 CodeDirectory"
    cd = blob[cd_idx[0][1]:]
    cd_magic, cd_len = struct.unpack_from(">II", cd, 0)
    if cd_magic != CSMAGIC_CODEDIRECTORY:
        return False, f"CodeDirectory magic={cd_magic:08x}"
    flags = bu32(cd, 12)
    if not (flags & CS_ADHOC):
        return False, f"flags=0x{flags:x}，缺 CS_ADHOC"
    version = bu32(cd, 8)
    hash_off, ident_off = bu32(cd, 16), bu32(cd, 20)
    nsp, ncs, code_limit = bu32(cd, 24), bu32(cd, 28), bu32(cd, 32)
    hs, ht, _, psz = struct.unpack_from(">BBBB", cd, 36)
    if (hs, ht, psz, nsp) != (HASH_SIZE, HASH_TYPE_SHA256, PAGE_SIZE_LOG2, 0):
        return False, f"签名参数 hs={hs} ht={ht} psz={psz} nsp={nsp}，与预期不符"

    # ★ 核心断言：header 长度由 version 决定，identOffset 必须落在 header 之后
    expect_hdr = cd_header_len(version)
    if expect_hdr > len(cd):
        return False, f"version=0x{version:x} 需要 {expect_hdr} 字节 header，CD 只有 {len(cd)}"
    if ident_off != expect_hdr:
        return False, (f"identOffset={ident_off} != version 0x{version:x} 要求的 header 长 "
                       f"{expect_hdr}（结构错位，系统会读错 execSeg 字段）")
    if hash_off <= ident_off or hash_off > len(cd):
        return False, f"hashOffset={hash_off} 不在 identOffset={ident_off} 之后"
    if b"\x00" not in cd[ident_off:hash_off]:
        return False, "identifier 没有 NUL 结尾"
    expect_len = hash_off + ncs * hs
    if cd_len != expect_len:
        return False, f"CD.length={cd_len} != hashOffset+nCodeSlots*hashSize={expect_len}"

    if code_limit != do:
        return False, f"codeLimit={code_limit} != dataoff={do}"
    expect = (code_limit + (1 << psz) - 1) // (1 << psz)
    if ncs != expect:
        return False, f"nCodeSlots={ncs} != {expect}"

    bad = []
    for i in range(ncs):
        s = i * (1 << psz)
        e = min(s + (1 << psz), code_limit)
        if hashlib.sha256(data[s:e]).digest() != cd[hash_off + i * hs:hash_off + (i + 1) * hs]:
            bad.append(i)
    if bad:
        return False, f"{len(bad)} 个 page hash 不符，首个={bad[0]}"

    # execSeg 必须与文件类型匹配（主程序标记 MAIN_BINARY，dylib 不标）
    base, limit, eflags = (struct.unpack_from(">Q", cd, 64)[0],
                           struct.unpack_from(">Q", cd, 72)[0],
                           struct.unpack_from(">Q", cd, 80)[0])
    ft = macho_filetype(data)
    if ft == MH_EXECUTE:
        if not (eflags & CS_EXECSEG_MAIN_BINARY):
            return False, f"主程序 execSegFlags=0x{eflags:x} 缺 CS_EXECSEG_MAIN_BINARY"
        text = find_segment(data, "__TEXT")
        if text and limit != text[2]:
            return False, f"execSegLimit={limit} != __TEXT.filesize={text[2]}"
    else:
        if eflags & CS_EXECSEG_MAIN_BINARY:
            return False, f"dylib 不应置 CS_EXECSEG_MAIN_BINARY（flags=0x{eflags:x}）"

    le_off, le_fo, le_fs = find_linkedit(data)
    if le_fo + le_fs != align8(len(data)):
        return False, f"__LINKEDIT end={le_fo+le_fs} != 对齐后文件长 {align8(len(data))}"
    if verbose:
        print(f"   签名 OK: slots={ncs} codeLimit={code_limit} flags=0x{flags:x} "
              f"hdr={expect_hdr} ident@{ident_off} hash@{hash_off} "
              f"execSeg=({base},0x{limit:x},0x{eflags:x}) blob={ds}")
    return True, "OK"


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        raise SystemExit("用法: adhoc_sign.py <macho> <identifier>")
    changed, n = sign_file(sys.argv[1], sys.argv[2])
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    ok, msg = verify_signature(data, verbose=True)
    print(f"{sys.argv[1]}: {'已签名' if changed else '原本已签名'} blob={n} verify={msg}")
    if not ok:
        raise SystemExit(1)