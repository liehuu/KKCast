#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 dylib 注入进一个已签名 iOS App 的可执行文件。

两个策略，按顺序尝试：

  策略 A（首选）：在 __TEXT 段 header 与首个 section 之间的**零填充**里
                 插入 LC_LOAD_DYLIB，cmdsize 增大。因为填充区全是 0，
                 插进去不移动任何已有字节，所有 vmaddr / fileoff 不变。
                 —— 可可影视这个包正好有 7424 字节空隙，够用。

  策略 B（兜底）：空隙不够时，把整个 __TEXT 段往后挪一页，腾出空间。
                 这要重算 __TEXT 里所有 section 的 offset、以及后面
                 所有段的 fileoff，还要改 LC_CODE_SIGNATURE。
                 能用 A 就不用 B，B 的出错面大得多。

关键点：
  · 插入后必须删除旧的 LC_CODE_SIGNATURE，否则签名 blob 对不上
    新的 load command 区，安装时报 "invalid signature"。
  · __LINKEDIT 段的 filesize 也要跟着改（签名 blobs 在它里面）。
"""

import argparse
import os
import shutil
import struct
import sys

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_BUILD_VERSION = 0x32
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_DYLIB_CODE_SIGN_DRS = 0x2B
LC_LINKER_OPTIMIZATION_HINT = 0x2E
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_CHAINED_FIXUPS = 0x80000034

# 这些 load command 带一个 fileoff+datasize 指针，__LINKEDIT 挪动时要一起改
LINKEDIT_POINTER_CMDS = {
    LC_SYMTAB, LC_DYSYMTAB, LC_DYLD_INFO, LC_DYLD_INFO_ONLY,
    LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLIB_CODE_SIGN_DRS,
    LC_LINKER_OPTIMIZATION_HINT, LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_CHAINED_FIXUPS,
}


def u32(b, o):
    return struct.unpack("<I", b[o:o + 4])[0]


def u64(b, o):
    return struct.unpack("<Q", b[o:o + 8])[0]


def p32(v):
    return struct.pack("<I", v)


def p64(v):
    return struct.pack("<Q", v)


class MachO:
    def __init__(self, data):
        self.data = bytearray(data)
        if u32(self.data, 0) != MH_MAGIC_64:
            raise SystemExit("只支持 thin arm64 的 MH_MAGIC_64")
        self.ncmds = u32(self.data, 16)
        self.sizeofcmds = u32(self.data, 20)
        self.header_size = 32
        self.cmds_end = self.header_size + self.sizeofcmds
        self.segments = self._parse_segments()

    def _parse_segments(self):
        segs = []
        off = self.header_size
        for _ in range(self.ncmds):
            cmd = u32(self.data, off)
            cmdsize = u32(self.data, off + 4)
            if cmd == LC_SEGMENT_64:
                name = bytes(self.data[off + 8:off + 24]).split(b"\x00")[0].decode()
                vmaddr = u64(self.data, off + 24)
                vmsize = u64(self.data, off + 32)
                fileoff = u64(self.data, off + 40)
                filesize = u64(self.data, off + 48)
                nsects = u32(self.data, off + 64)
                segs.append({
                    "cmd_off": off, "name": name, "vmaddr": vmaddr,
                    "vmsize": vmsize, "fileoff": fileoff,
                    "filesize": filesize, "nsects": nsects,
                })
            off += cmdsize
        return segs

    def text_seg(self):
        for s in self.segments:
            if s["name"] == "__TEXT":
                return s
        raise SystemExit("找不到 __TEXT 段")

    def linkedit_seg(self):
        for s in self.segments:
            if s["name"] == "__LINKEDIT":
                return s
        raise SystemExit("找不到 __LINKEDIT 段")

    def first_section_offset(self):
        t = self.text_seg()
        off = t["cmd_off"] + 72
        best = None
        for _ in range(t["nsects"]):
            addr = u64(self.data, off + 32)
            size = u64(self.data, off + 40)
            foff = u32(self.data, off + 48)
            sname = bytes(self.data[off:off + 16]).split(b"\x00")[0].decode()
            if size > 0 and (best is None or foff < best[1]):
                best = (sname, foff, addr, size)
            off += 80
        return best

    def slack(self):
        """header 与首个 section 之间的可用字节数。"""
        sec = self.first_section_offset()
        if not sec:
            return 0, None
        return sec[1] - self.cmds_end, sec

    def slack_all_zero(self):
        n, _ = self.slack()
        if n <= 0:
            return True
        return set(self.data[self.cmds_end:self.cmds_end + n]) == {0}

    def find_cmd_offsets(self, target_cmd):
        res = []
        off = self.header_size
        for _ in range(self.ncmds):
            cmd = u32(self.data, off)
            cmdsize = u32(self.data, off + 4)
            if cmd == target_cmd:
                res.append((off, cmdsize))
            off += cmdsize
        return res


def build_dylib_cmd(path, timestamp=2):
    """构造 LC_LOAD_DYLIB（其实是 LC_LOAD_DYLIB 的 24 字节头 + 名字 + 补齐）。

    dylib_command {
        uint32 cmd; uint32 cmdsize;
        dylib name(lc_str offset, timestamp, current_version, compatibility_version);
    }
    """
    name_bytes = path.encode("utf-8") + b"\x00"
    # 头 24 字节（cmd 4 + cmdsize 4 + name offset 4 + timestamp 4 + cur 4 + compat 4）
    header_len = 24
    total = header_len + len(name_bytes)
    # 8 字节对齐
    aligned = (total + 7) & ~7
    pad = aligned - total

    cmd = p32(LC_LOAD_DYLIB) + p32(aligned)
    cmd += p32(header_len)          # name offset，从 cmd 起始算
    cmd += p32(timestamp)
    cmd += p32(0x00010000)          # current_version 1.0.0
    cmd += p32(0x00010000)          # compatibility_version 1.0.0
    cmd += name_bytes + b"\x00" * pad
    assert len(cmd) == aligned, (len(cmd), aligned)
    return cmd


def inject_inplace(macho, dylib_path):
    """策略 A：把 LC_LOAD_DYLIB 写进现有零填充，不移动任何数据。"""
    avail, sec = macho.slack()
    if not macho.slack_all_zero():
        raise SystemExit(
            f"header 后的 {avail} 字节不是全零，就地插入会破坏已有数据，拒绝执行")

    cmd = build_dylib_cmd(dylib_path)
    need = len(cmd)
    print(f"  首个 section: {sec[0]} @ fileoff 0x{sec[1]:x}")
    print(f"  可用空隙: {avail} 字节，需要: {need} 字节")

    if need > avail:
        raise SystemExit(f"空隙不足（需 {need}，仅 {avail}），需要走策略 B（本次未实现）")

    # 1. 写 load command 到 cmds_end
    start = macho.cmds_end
    macho.data[start:start + need] = cmd

    # 2. 更新 header 的 ncmds / sizeofcmds
    macho.data[16:20] = p32(macho.ncmds + 1)
    macho.data[20:24] = p32(macho.sizeofcmds + need)

    print(f"  ncmds {macho.ncmds} → {macho.ncmds + 1}")
    print(f"  sizeofcmds 0x{macho.sizeofcmds:x} → 0x{macho.sizeofcmds + need:x}")
    return macho.data


def strip_codesig(macho):
    """删掉 LC_CODE_SIGNATURE 命令本身，并把 __LINKEDIT.filesize 收缩到签名前。

    不删的后果：新插入的 load command 让 CS_CodeDirectory 里记录的
    codeLimit（被签名覆盖的文件长度）与实际不符，设备校验直接拒装。
    重签时会重新生成，所以这里删掉是正确做法。
    """
    hits = macho.find_cmd_offsets(LC_CODE_SIGNATURE)
    if not hits:
        print("  没有 LC_CODE_SIGNATURE，跳过")
        return macho.data, 0

    total_removed = 0
    dataoff = datasz = None
    # 从后往前删，避免偏移失效
    for off, cmdsize in sorted(hits, reverse=True):
        if off + 16 <= len(macho.data):
            dataoff = u32(macho.data, off + 8)
            datasz = u32(macho.data, off + 12)
        del macho.data[off:off + cmdsize]
        total_removed += cmdsize

    # ncmds 减、sizeofcmds 减
    n = u32(macho.data, 16) - len(hits)
    s = u32(macho.data, 20) - total_removed
    macho.data[16:20] = p32(n)
    macho.data[20:24] = p32(s)

    print(f"  删除 LC_CODE_SIGNATURE {len(hits)} 条（{total_removed} 字节），"
          f"dataoff=0x{dataoff:x} datasize={datasz}")

    # __LINKEDIT 收尾：签名数据被丢弃，filesize 缩到 dataoff
    if dataoff:
        le = macho.linkedit_seg()
        le_end = le["fileoff"] + le["filesize"]

        # 关键保护：只有当签名确实位于 __LINKEDIT 的**最末端**时，
        # 才能安全地把 filesize 收缩到 dataoff 并截断文件。
        # 如果签名之后还有别的数据（符号表、字符串表等），
        # 无条件收缩会把那些数据一起丢掉——链接器读不到符号表，
        # dyld 起不来，表现为"装上去点开就闪退"。
        sig_end = dataoff + (datasz or 0)
        slack = le_end - sig_end

        if slack > 0:
            # 签名后面还有数据，不能截断。只把签名区域保留原样
            # （重签会覆盖它），filesize 保持不动。
            print(f"  ⚠️  签名后仍有 {slack} 字节数据，不收缩 __LINKEDIT"
                  f"（保留原 filesize 0x{le['filesize']:x}，避免截掉符号表）")
        else:
            new_size = dataoff - le["fileoff"]
            if new_size > 0 and new_size <= le["filesize"]:
                macho.data[le["cmd_off"] + 48:le["cmd_off"] + 56] = p64(new_size)
                print(f"  __LINKEDIT.filesize 0x{le['filesize']:x} → 0x{new_size:x}")
                macho.data = macho.data[:dataoff]
                print(f"  文件截断到 0x{dataoff:x}（{dataoff} 字节）")

    return macho.data, total_removed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", help="宿主可执行文件")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--dylib", default="@executable_path/Frameworks/KKCast.dylib")
    ap.add_argument("--keep-signature", action="store_true",
                    help="保留原签名（调试用，正常不要加）")
    args = ap.parse_args()

    with open(args.binary, "rb") as f:
        raw = f.read()

    print(f"输入: {args.binary}  {len(raw)} 字节")
    m = MachO(raw)
    print(f"ncmds={m.ncmds} sizeofcmds=0x{m.sizeofcmds:x} cmds_end=0x{m.cmds_end:x}")

    for s in m.segments:
        print(f"  {s['name']:14s} vm=0x{s['vmaddr']:x} fileoff=0x{s['fileoff']:x} "
              f"filesize=0x{s['filesize']:x}")

    print("\n[1] 注入 LC_LOAD_DYLIB")
    data = inject_inplace(m, args.dylib)

    # 重新解析，因为 ncmds 变了
    m2 = MachO(bytes(data))

    if not args.keep_signature:
        print("\n[2] 剥离旧签名")
        data, _ = strip_codesig(m2)

    print("\n[3] 校验结果")
    m3 = MachO(bytes(data))
    print(f"  ncmds={m3.ncmds} sizeofcmds=0x{m3.sizeofcmds:x}")
    # 确认新命令在
    found = False
    off = m3.header_size
    for _ in range(m3.ncmds):
        cmd = u32(m3.data, off)
        cmdsize = u32(m3.data, off + 4)
        if cmd == LC_LOAD_DYLIB:
            noff = u32(m3.data, off + 8)
            name = bytes(m3.data[off + noff:off + cmdsize]).split(b"\x00")[0].decode()
            print(f"  ✅ LC_LOAD_DYLIB: {name}")
            found = True
        off += cmdsize
    if not found:
        raise SystemExit("❌ 注入失败：找不到 LC_LOAD_DYLIB")

    with open(args.output, "wb") as f:
        f.write(data)
    print(f"\n输出: {args.output}  {len(data)} 字节")
    print(f"大小变化: {len(raw)} → {len(data)} ({len(data) - len(raw):+d})")


if __name__ == "__main__":
    main()