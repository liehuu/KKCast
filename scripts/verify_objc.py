#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Objective-C 源码静态契约检查。

为什么需要这个：
  本机没有 Xcode 工具链，源码要推到 GitHub Actions 才第一次真正编译。
  一个拼错的大括号、一个声明了却没实现的方法，会在 CI 上浪费一整轮
  （拉取 + 编译≈6 分钟）。更糟的是这类错误**没有任何语义**，
  纯粹是搬运时漏了，靠人眼复查很容易漏。

  所以这里做机械对照：括号配平、@interface/@implementation 区块配对、
  声明 vs 实现的方法名差集。

判据全部基于**剥离注释与字符串后的代码**：
  直接对原文做括号计数会被注释里的 "（" 和字符串里的 "{" 带偏，
  这一点我在写 UnCast 的 verify_ssdp.py 时踩过。
"""

import re
import sys
import os

FAIL = []


def fail(msg):
    FAIL.append(msg)
    print(f"  ❌ {msg}")


def ok(msg):
    print(f"  ✅ {msg}")


def strip_comments_and_strings(src):
    """把注释和字符串字面量替换成等长空白，保持字符偏移不变。

    不用简单的 re.sub：`//` 出现在字符串里（如 url 里的 http://）
    会被误判成注释起点，导致后面的代码被整段吃掉。
    用一个手写状态机逐字符走。
    """
    out = []
    i = 0
    n = len(src)
    state = "code"          # code | line_comment | block_comment | string | char
    while i < n:
        c = src[i]
        nx = src[i + 1] if i + 1 < n else ""

        if state == "code":
            if c == "/" and nx == "/":
                state = "line_comment"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nx == "*":
                state = "block_comment"
                out.append("  ")
                i += 2
                continue
            if c == '"':
                state = "string"
                out.append(" ")
                i += 1
                continue
            if c == "'":
                state = "char"
                out.append(" ")
                i += 1
                continue
            out.append(c)
            i += 1
            continue

        if state == "line_comment":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if c == "*" and nx == "/":
                state = "code"
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue

        if state == "string":
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == '"':
                state = "code"
                out.append(" ")
                i += 1
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue

        if state == "char":
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if c == "'":
                state = "code"
                out.append(" ")
                i += 1
                continue
            out.append(" ")
            i += 1
            continue

    return "".join(out)


def check_braces(clean, name):
    """括号 / 圆括号配平。"""
    for open_ch, close_ch, label in [("{", "}", "大括号"), ("(", ")", "圆括号")]:
        depth = 0
        for idx, c in enumerate(clean):
            if c == open_ch:
                depth += 1
            elif c == close_ch:
                depth -= 1
                if depth < 0:
                    line = clean[:idx].count("\n") + 1
                    fail(f"{name}:{line} {label} 多闭合")
                    return False
        if depth != 0:
            fail(f"{name} {label} 不配平，剩余深度 {depth}")
            return False
    ok(f"{name} 括号配平")
    return True


def split_blocks(clean):
    """把源码切成 [(kind, name, body)]，kind 为 interface/implementation。"""
    blocks = []
    pat = re.compile(r"@(interface|implementation)\s+([A-Za-z_]\w*)")
    matches = list(pat.finditer(clean))
    for i, m in enumerate(matches):
        start = m.end()
        # 找到配对的 @end：从 start 开始数 @interface/@implementation，遇 @end 抵消
        depth = 1
        pos = start
        end = None
        tok = re.compile(r"@(interface|implementation|end)\b")
        while True:
            t = tok.search(clean, pos)
            if not t:
                break
            if t.group(1) in ("interface", "implementation"):
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    end = t.start()
                    break
            pos = t.end()
        if end is None:
            blocks.append((m.group(1), m.group(2), None))
        else:
            blocks.append((m.group(1), m.group(2), clean[start:end]))
    return blocks


def method_decls(body):
    """从 interface 体里抽方法声明名。

    只取以 - 或 + 开头的行，且在 ; 之前。注意要处理跨行声明：
    `- (void)foo:(int)a\n   bar:(int)b;` 这种，名字是第一个选择器段。
    """
    names = set()
    for m in re.finditer(r"^[ \t]*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)", body, re.M):
        names.add(m.group(1))
    return names


def method_impls(body):
    names = set()
    for m in re.finditer(r"^[ \t]*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)", body, re.M):
        names.add(m.group(1))
    return names


def check_files(paths):
    print("=" * 66)
    print("1. 括号配平")
    print("=" * 66)
    cleaned = {}
    for p in paths:
        with open(p, "r", encoding="utf-8") as f:
            src = f.read()
        clean = strip_comments_and_strings(src)
        cleaned[p] = clean
        check_braces(clean, os.path.basename(p))

    print()
    print("=" * 66)
    print("2. @interface / @implementation 配对")
    print("=" * 66)
    for p, clean in cleaned.items():
        blocks = split_blocks(clean)
        name = os.path.basename(p)
        incomplete = [b for b in blocks if b[2] is None]
        if incomplete:
            for b in incomplete:
                fail(f"{name}: @{b[0]} {b[1]} 没有配对的 @end")
        else:
            ok(f"{name}: {len(blocks)} 个 block 全部闭合")

    print()
    print("=" * 66)
    print("3. 声明 vs 实现 差集（跨文件）")
    print("=" * 66)
    # 关键：声明和实现通常不在同一个文件里（.h 声明、.m 实现）。
    # 早先只比同文件内的差集，于是头文件里声明的 KKDLNA /
    # KKProxyServer / KKCastUI 全部漏检——报告"声明 0 个方法"，
    # 恒真通过。这种检查等于不存在，必须先全局汇总再比。
    all_decls = {}      # cls -> {mname: (file, line)}
    all_impls = {}      # cls -> {mname: file}

    for p, clean in cleaned.items():
        blocks = split_blocks(clean)
        fname = os.path.basename(p)
        for kind, cls, body in blocks:
            if body is None:
                continue
            if kind == "interface":
                d = all_decls.setdefault(cls, {})
                for m in re.finditer(r"^[ \t]*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)", body, re.M):
                    # body 是从 interface 名之后开始的，需要还原绝对行号
                    abs_off = clean.find(body) + m.start() if body in clean else 0
                    line = clean[:abs_off].count("\n") + 1
                    d.setdefault(m.group(1), (fname, line))
            else:
                all_impls.setdefault(cls, set()).update(
                    m.group(1) for m in
                    re.finditer(r"^[ \t]*[-+]\s*\([^)]*\)\s*([A-Za-z_]\w*)", body, re.M))

    # 只对"有实现类"的类做差集：纯协议/@interface-only 不判失败
    checked = 0
    for cls, ds in sorted(all_decls.items()):
        if cls not in all_impls:
            print(f"  ⚠️  {cls}: 只有 @interface，全局没有 @implementation（可能是纯声明）")
            continue
        missing = set(ds) - all_impls[cls]
        if missing:
            for m in sorted(missing):
                f, ln = ds[m]
                fail(f"{cls} 在 {f}:{ln} 声明了 -{m} 但没有实现")
        else:
            ok(f"{cls}: 声明 {len(ds)} 个方法，全部有实现")
            checked += 1

    if checked == 0:
        fail("没有任何类完成声明/实现对照 —— 这个检查实际上没生效")
    else:
        print(f"  （实际对照了 {checked} 个类）")

    print()
    print("=" * 66)
    print("4. 关键常量一致性")
    print("=" * 66)
    # 注意：这一组必须查**原文**，不能查剥离后的 clean。
    # AVURLAssetHTTPHeaderFieldsKey 是字符串字面量的值，
    # 剥离器会把字符串内容抹成空格，于是永远匹配不到 —— 假 FAIL。
    # 判据要盯的是"这个 key 是否出现在源码里"，查原文才对。
    hook_raw = None
    for p in paths:
        if p.endswith("KKHook.m"):
            with open(p, "r", encoding="utf-8") as f:
                hook_raw = f.read()
    if hook_raw:
        if 'AVURLAssetHTTPHeaderFieldsKey' in hook_raw:
            ok("KKHook.m 使用 AVURLAssetHTTPHeaderFieldsKey")
        else:
            fail("KKHook.m 里找不到 AVURLAssetHTTPHeaderFieldsKey")
        # 这个 key 必须是 @"..." 形式（字符串），不能是裸标识符
        if re.search(r'@"AVURLAssetHTTPHeaderFieldsKey"', hook_raw):
            ok("key 以字符串字面量形式定义")
        else:
            fail("key 不是 @\"...\" 字符串字面量，运行时会崩")

    if FAIL:
        print()
        print(f"结论：FAIL（{len(FAIL)} 项）")
        return 1
    print()
    print("结论：PASS")
    return 0


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src_dir = os.path.join(root, "KKCast")
    paths = []
    for fn in sorted(os.listdir(src_dir)):
        if fn.endswith(".m") or fn.endswith(".h"):
            paths.append(os.path.join(src_dir, fn))
    if not paths:
        raise SystemExit("没有找到源码文件")
    print(f"检查 {len(paths)} 个文件：")
    for p in paths:
        print(f"  {os.path.basename(p)}")
    print()
    return check_files(paths)


if __name__ == "__main__":
    sys.exit(main())