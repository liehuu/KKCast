#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""拆解 Apple 原包签名：逐 blob 列出，导出 Entitlements / Requirements。

不猜格式：SuperBlob 索引 + CodeDirectory 大端，逐字段打印。
"""
import struct
import sys

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_BLOBWRAPPER = 0xFADE0B01
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_REQUIREMENTS = 0xFADE0C01
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172

BLOB_NAMES = {
    0: "CodeDirectory",
    1: "Info.plist",
    2: "Requirements",
    3: "ResourceDir",
    4: "Application",
    5: "Entitlements",
    7: "DER Entitlements",
    0x10000: "CMS Signature",
}
SLOT_OF_TYPE = {0: 0, 2: 2, 3: -1, 5: -2, 7: -3}
TYPE_NAMES = {0: "CSSLOT_CODEDIRECTORY", 2: "CSSLOT_REQUIREMENTS",
              3: "CSSLOT_RESOURCEDIR", 5: "CSSLOT_ENTITLEMENTS",
              7: "CSSLOT_DER_ENTITLEMENTS", 0x10000: "CSSLOT_SIGNATURESLOT"}

LC_CODE_SIGNATURE = 0x1D


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def bu32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def find_codesig(data):
    if u32(data, 0) != 0xFEEDFACF:
        raise ValueError("不是 MH_MAGIC_64")
    ncmds, off = u32(data, 16), 32
    for _ in range(ncmds):
        cmd, cs = u32(data, off), u32(data, off + 4)
        if cmd == LC_CODE_SIGNATURE:
            return u32(data, off + 8), u32(data, off + 12)
        off += cs
    return None, None


def dump(path, outdir=None):
    data = open(path, "rb").read()
    do, ds = find_codesig(data)
    print(f"\n=== {path} ===")
    if do is None:
        print("  !! 无 LC_CODE_SIGNATURE")
        return
    print(f"  LC_CODE_SIGNATURE dataoff={do} datasize={ds} filesize={len(data)}")
    blob = data[do:do + ds]
    magic, length, count = struct.unpack_from(">III", blob, 0)
    print(f"  SuperBlob magic=0x{magic:08x} length={length} count={count} "
          f"{'✓' if magic == CSMAGIC_EMBEDDED_SIGNATURE else '✗'}")
    for i in range(count):
        typ, off_ = struct.unpack_from(">II", blob, 12 + 8 * i)
        bm, bl = struct.unpack_from(">II", blob, off_)
        print(f"   [{i}] type=0x{typ:x} ({BLOB_NAMES.get(typ, TYPE_NAMES.get(typ, '同 type'))}) "
              f"off={off_} magic=0x{bm:08x} len={bl}")
        if typ == 0:
            cd = blob[off_:]
            ver = bu32(cd, 8)
            flags = bu32(cd, 12)
            hash_off, ident_off = bu32(cd, 16), bu32(cd, 20)
            nsp, ncs, climit = bu32(cd, 24), bu32(cd, 28), bu32(cd, 32)
            hs, ht, _, psz = struct.unpack_from(">BBBB", cd, 36)
            ident = cd[ident_off:].split(b"\x00")[0].decode("utf-8", "replace")
            print(f"       version=0x{ver:x} flags=0x{flags:x} ident={ident}")
            print(f"       nSpecialSlots={nsp} nCodeSlots={ncs} codeLimit={climit} "
                  f"hashSize={hs} hashType={ht} pageSize=2^{psz}")
            # 特殊槽反向解读：槽 -k 位于 hashOffset - k*hashSize
            for k in range(1, nsp + 1):
                pos = hash_off - k * hs
                h = cd[pos:pos + hs]
                print(f"       special slot -{k} @cd[{pos}] = {h.hex()}")
            if outdir:
                # 导出 Entitlements
                for k in range(1, nsp + 1):
                    pass
        if typ == 5 and outdir:
            p = outdir + "/entitlements.der.plist"
            open(p, "wb").write(blob[off_:off_ + bl])
            print(f"       → 已导出 {p}")
            try:
                import plistlib
                obj = plistlib.loads(blob[off_ + 8:off_ + bl])
                import json
                print("       Entitlements 内容:")
                print("       " + json.dumps(obj, indent=2, ensure_ascii=False).replace("\n", "\n       "))
            except Exception as e:
                print(f"       plist 解析失败: {e}")


outdir = None
args = sys.argv[1:]
if args and args[0].startswith("--out="):
    outdir = args[0][6:]
    args = args[1:]
for p in args:
    dump(p, outdir)