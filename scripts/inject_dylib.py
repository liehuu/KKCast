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
    """策略 A：把 LC_LOAD_DYLIB 写进现有零填充，不移动任何数据。

    ★ 与 strip_codesig 同一条铁律：绝不 insert，只覆盖零填充。
      任何"在文件中间插入字节"的操作都会让其后所有内容位移，
      而段的 fileoff 与各 dataoff 不会跟着改 —— dyld 读到错位数据，
      启动即崩。这条约束比"能不能塞下"重要得多。
    """
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

    # 1. 覆盖写入 load command（不 insert，长度不变）
    start = macho.cmds_end
    macho.data[start:start + need] = cmd

    # 2. 更新 header 的 ncmds / sizeofcmds
    macho.data[16:20] = p32(macho.ncmds + 1)
    macho.data[20:24] = p32(macho.sizeofcmds + need)

    print(f"  ncmds {macho.ncmds} → {macho.ncmds + 1}")
    print(f"  sizeofcmds 0x{macho.sizeofcmds:x} → 0x{macho.sizeofcmds + need:x}")
    return macho.data


def strip_codesig(macho):
    """删掉 LC_CODE_SIGNATURE 命令本身，**但不移动任何被引用的字节**。

    ★ v1 的致命错误（真机"出现进入画面就闪退"的真正根因）：
      旧实现 `del macho.data[off:off+cmdsize]` 把 16 字节命令从文件中间
      抠掉，导致其后**所有字节整体前移 16**，而段的 fileoff 与各 load
      command 里的 dataoff（CHAINED_FIXUPS / EXPORTS_TRIE / SYMTAB /
      FUNCTION_STARTS）全都没跟着改。

      实测 movie.orig → movie.patched：
        __TEXT 首节      16384   → 16368   (-16)
        __DATA_CONST   9977856  → 9977840 (-16)
        __DATA        10354688  → 10354672 (-16)
        __LINKEDIT    10780672  → 10780656 (-16)
      而 LC_DYLD_CHAINED_FIXUPS.dataoff 仍写 10780672。
      dyld 到位移后的错误位置读 header，得到
        (3249, 1, 0, 0, 5, 0, 0)   ← 应该是 (0, 32, 204, 13200, 3249, 1, 0)
      imports_format=0 非法，绑定阶段 abort。
      表现就是"看到启动画面，随即闪退"—— 和签名问题外观完全一样，
      所以前两轮修签名都没修对地方。

    ★ 正确做法：只在 load command 区内左移，尾部零填充。
      load command 区（32..lc_end）不承载任何"被 dataoff 引用"的数据，
      而 lc_end 之后到首个 section 之间是链接器留的零填充。
      所以：把 [end, lc_end) 左移 cmdsize，末尾补零，ncmds/sizeofcmds 各减。
      文件长度不变 → 所有 fileoff/dataoff 继续有效。
    """
    hits = macho.find_cmd_offsets(LC_CODE_SIGNATURE)
    if not hits:
        print("  没有 LC_CODE_SIGNATURE，跳过")
        return macho.data, 0

    dataoff = datasz = None
    for off, cmdsize in hits:
        dataoff = u32(macho.data, off + 8)
        datasz = u32(macho.data, off + 12)

    lc_end = macho.header_size + macho.sizeofcmds
    total_removed = 0
    # 从后往前处理，前面 cmd 的偏移不受影响；lc_end 逐次收缩
    for off, cmdsize in sorted(hits, reverse=True):
        tail_start = off + cmdsize
        if tail_start > lc_end:
            raise SystemExit(f"LC_CODE_SIGNATURE 越出 cmds 区: {off}+{cmdsize} > {lc_end}")
        # [tail_start, lc_end) 整体左移 cmdsize
        macho.data[off:lc_end - cmdsize] = macho.data[tail_start:lc_end]
        # 尾部补零（落回原来的零填充区，不碰任何 section）
        macho.data[lc_end - cmdsize:lc_end] = b"\x00" * cmdsize
        lc_end -= cmdsize
        total_removed += cmdsize

    # ncmds 减、sizeofcmds 减
    macho.data[16:20] = p32(u32(macho.data, 16) - len(hits))
    macho.data[20:24] = p32(u32(macho.data, 20) - total_removed)

    print(f"  删除 LC_CODE_SIGNATURE {len(hits)} 条（{total_removed} 字节，"
          f"仅左移 cmds 区并零填充，文件长度不变），"
          f"dataoff=0x{dataoff:x} datasize={datasz}")

    # __LINKEDIT 收尾：旧签名 blob 在文件尾部，截掉它。
    # 只截 [dataoff, EOF)，不移动任何前面的字节，所以 fileoff 全部仍有效。
    if dataoff:
        le = macho.linkedit_seg()
        le_end = le["fileoff"] + le["filesize"]
        sig_end = dataoff + (datasz or 0)

        if sig_end != le_end:
            # 签名后面还有别的数据（符号表等）。只把 filesize 收到 dataoff，
            # 不截断文件，避免丢掉数据。
            new_size = dataoff - le["fileoff"]
            if 0 < new_size <= le["filesize"]:
                macho.data[le["cmd_off"] + 48:le["cmd_off"] + 56] = p64(new_size)
                print(f"  __LINKEDIT.filesize 0x{le['filesize']:x} → 0x{new_size:x}"
                      f"（签名后仍有 {le_end - sig_end} 字节数据，不截断）")
        else:
            new_size = dataoff - le["fileoff"]
            if 0 < new_size <= le["filesize"]:
                macho.data[le["cmd_off"] + 48:le["cmd_off"] + 56] = p64(new_size)
                before = len(macho.data)
                macho.data = macho.data[:dataoff]
                print(f"  __LINKEDIT.filesize 0x{le['filesize']:x} → 0x{new_size:x}，"
                      f"截掉尾部旧签名 {before - dataoff} 字节（前面字节未移动）")

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