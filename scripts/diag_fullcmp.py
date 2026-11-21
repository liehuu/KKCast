#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""完整字节级对照：正文区全量比较 + load command 逐条 diff。

为什么必须全量：
  上次只抽查了 __TEXT 尾部 1MB，就宣布"内容相同"。首节 __text 有 9961472
  字节，抽查覆盖不到 11%。判据必须覆盖全部字节，否则是装饰。
"""
import hashlib
import struct
import sys

LC_SEGMENT_64 = 0x19
LC_CODE_SIGNATURE = 0x1D

NAMES = {
    0x2: "LC_SYMTAB", 0xB: "LC_DYSYMTAB", 0xC: "LC_LOAD_DYLIB", 0xD: "LC_ID_DYLIB",
    0xE: "LC_LOAD_DYLINKER", 0xF: "LC_ID_DYLINKER", 0x19: "LC_SEGMENT_64",
    0x1B: "LC_UUID", 0x1D: "LC_CODE_SIGNATURE", 0x22: "LC_DYLD_INFO",
    0x80000022: "LC_DYLD_INFO_ONLY", 0x26: "LC_FUNCTION_STARTS",
    0x29: "LC_DATA_IN_CODE", 0x2B: "LC_DYLIB_CODE_SIGN_DRS",
    0x2E: "LC_LINKER_OPTIMIZATION_HINT", 0x32 | 0x80000000: "LC_BUILD_VERSION",
    0x80000033: "LC_DYLD_EXPORTS_TRIE", 0x80000034: "LC_DYLD_CHAINED_FIXUPS",
    0x24 | 0x80000000: "LC_VERSION_MIN_IPHONEOS", 0x21 | 0x80000000: "LC_ENCRYPTION_INFO_64",
    0x80000028: "LC_MAIN", 0x1C | 0x80000000: "LC_RPATH",
    0x18 | 0x80000000: "LC_LOAD_WEAK_DYLIB", 0x1F | 0x80000000: "LC_REEXPORT_DYLIB",
    0x20 | 0x80000000: "LC_LOAD_UPWARD_DYLIB", 0x23 | 0x80000000: "LC_LAZY_LOAD_DYLIB",
    0x80000035: "LC_ATOM_INFO",
}


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def lc_list(data):
    ncmds, off = u32(data, 16), 32
    out = []
    for _ in range(ncmds):
        cmd, cs = u32(data, off), u32(data, off + 4)
        body = bytes(data[off:off + cs])
        out.append((off, cmd, cs, body))
        off += cs
    return out


def seg_table(data):
    t = {}
    off = 32
    for _ in range(u32(data, 16)):
        cmd, cs = u32(data, off), u32(data, off + 4)
        if cmd == LC_SEGMENT_64:
            name = bytes(data[off + 8:off + 24]).split(b"\x00")[0].decode("ascii", "replace")
            t[name] = (u64(data, off + 40), u64(data, off + 48))
        off += cs
    return t


def sha(b):
    return hashlib.sha256(b).hexdigest()


A = open(sys.argv[1], "rb").read()
B = open(sys.argv[2], "rb").read()

print(f"A={sys.argv[1]}  {len(A)} bytes")
print(f"B={sys.argv[2]}  {len(B)} bytes")

la, lb = lc_list(A), lc_list(B)
print(f"\n--- load command 逐条对照 ---")
print(f"A: ncmds={len(la)} sizeofcmds={u32(A,20)}  cmds_end={32+u32(A,20)}")
print(f"B: ncmds={len(lb)} sizeofcmds={u32(B,20)}  cmds_end={32+u32(B,20)}")

# 按 (cmd, 内容摘要) 做多重集合比较，找出新增/删除/变化
from collections import Counter


def key_of(cmd, body):
    if cmd == LC_SEGMENT_64:
        name = body[8:24].split(b"\x00")[0].decode("ascii", "replace")
        return (cmd, name, body)
    return (cmd, "", body)


ca = Counter(key_of(c, b) for _, c, _, b in la)
cb = Counter(key_of(c, b) for _, c, _, b in lb)

only_a = ca - cb
only_b = cb - ca
print(f"\n只在 A 中出现（被删或变更）: {sum(only_a.values())} 条")
for (cmd, name, body), n in only_a.items():
    print(f"  - {NAMES.get(cmd, hex(cmd)):<26} {name:<16} cmdsize={u32(body,4)} x{n}")
    if cmd == LC_SEGMENT_64:
        print(f"      fileoff={u64(body,40)} filesize={u64(body,48)}")
print(f"\n只在 B 中出现（新增或变更）: {sum(only_b.values())} 条")
for (cmd, name, body), n in only_b.items():
    print(f"  + {NAMES.get(cmd, hex(cmd)):<26} {name:<16} cmdsize={u32(body,4)} x{n}")
    if cmd == LC_SEGMENT_64:
        print(f"      fileoff={u64(body,40)} filesize={u64(body,48)}")

# 正文全量比较：首节 16384 起，到 __TEXT 段尾
sa, sb = seg_table(A), seg_table(B)
ta, tb = sa["__TEXT"], sb["__TEXT"]
print(f"\n--- 正文全量逐字节比较 ---")
print(f"__TEXT  A: fileoff={ta[0]} filesize={ta[1]} end={ta[0]+ta[1]}")
print(f"__TEXT  B: fileoff={tb[0]} filesize={tb[1]} end={tb[0]+tb[1]}")
assert ta == tb, "两个 __TEXT 段的 fileoff/filesize 不一致，前提交付已破"

begin = 16384                      # 首节 __text 的绝对偏移
end = ta[0] + ta[1]                # __TEXT 段尾
n = end - begin
print(f"比较范围 [{begin}, {end})  共 {n} 字节 ({n/1024/1024:.2f} MB)")
ca_ = A[begin:end]
cb_ = B[begin:end]
print(f"sha A={sha(ca_)}")
print(f"sha B={sha(cb_)}")
print(f"结论: {'✓ 逐字节完全相同' if ca_ == cb_ else '✗ 存在差异'}")

if ca_ != cb_:
    diffs = [i for i in range(n) if ca_[i] != cb_[i]]
    print(f"差异 {len(diffs)} 字节")
    print(f"首个差异绝对偏移 {begin + diffs[0]}")
    # 聚类区间
    runs = []
    s = diffs[0]
    p = diffs[0]
    for d in diffs[1:]:
        if d - p > 64:
            runs.append((s, p))
            s = d
        p = d
    runs.append((s, p))
    print(f"差异聚为 {len(runs)} 段，前 10 段:")
    for s, e in runs[:10]:
        print(f"  [{begin+s}, {begin+e}]  {e-s+1} 字节")
        print(f"    A: {ca_[s:s+32].hex()}")
        print(f"    B: {cb_[s:s+32].hex()}")

# __DATA_CONST / __DATA 全量
for nm in ("__DATA_CONST", "__DATA"):
    x, y = sa[nm], sb[nm]
    a_ = A[x[0]:x[0] + x[1]]
    b_ = B[y[0]:y[0] + y[1]]
    same = a_ == b_
    print(f"\n{nm}: A[{x[0]},{x[0]+x[1]}) B[{y[0]},{y[0]+y[1]})  "
          f"{'✓ 逐字节相同' if same else '✗ 有差异'}")
    if not same and len(a_) == len(b_):
        d = [i for i in range(len(a_)) if a_[i] != b_[i]]
        print(f"   差异 {len(d)} 字节，首个 @+{d[0]} (绝对 {x[0]+d[0]})")