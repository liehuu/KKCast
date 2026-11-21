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

    print()
    print("=" * 66)
    print("5. 代理写 socket 的不变量（快进卡死 / 投屏闪退的回归门禁）")
    print("=" * 66)
    # 这一组盯的是 KKProxy.m 里两条已经被真机证实过的缺陷。
    # 只查剥离后的代码（clean），注释里提到 send 不算数。
    proxy_clean = None
    for p, c in cleaned.items():
        if p.endswith("KKProxy.m"):
            proxy_clean = c
    if proxy_clean is None:
        fail("没有找到 KKProxy.m，无法检查代理不变量")
    else:
        # (1) 所有 send 必须经过 kk_send_all 这一层。
        #
        # 为什么这是一条硬不变量：client fd 上设了 SO_SNDTIMEO，电视
        # 快进时会短暂不读 socket，裸 send 会超时返回 -1/EAGAIN。
        # 把 EAGAIN 当成"对端断开"，就会在用户按快进时主动断流，
        # 表现为进度条停在快进位置不动。kk_send_all 会区分
        # "暂时写不进去"与"真断开"，所以裸 send 不允许出现在别处。
        raw_send_lines = []
        for m in re.finditer(r"\bsend\s*\(", proxy_clean):
            line_no = proxy_clean[:m.start()].count("\n") + 1
            raw_send_lines.append(line_no)
        # kk_send_all 内部那一处是唯一允许的
        func = re.search(r"static\s+size_t\s+kk_send_all\s*\(", proxy_clean)
        if not func:
            fail("KKProxy.m 里没有 kk_send_all，写 socket 没有统一出口")
        else:
            body_start = proxy_clean.index("{", func.end())
            depth = 0
            body_end = None
            for i in range(body_start, len(proxy_clean)):
                if proxy_clean[i] == "{":
                    depth += 1
                elif proxy_clean[i] == "}":
                    depth -= 1
                    if depth == 0:
                        body_end = i
                        break
            fn_lo = proxy_clean[:body_start].count("\n") + 1
            fn_hi = proxy_clean[:body_end].count("\n") + 1 if body_end else fn_lo
            strays = [l for l in raw_send_lines if not (fn_lo <= l <= fn_hi)]
            if strays:
                fail(f"KKProxy.m: 有裸 send 绕过 kk_send_all（行 {strays}）"
                     f" —— 快进时 EAGAIN 会被误判为断开")
            else:
                ok(f"所有 send 都经过 kk_send_all（1 处实现，外部 0 处裸调用）")

        # (2) errno == EAGAIN 必须在 **kk_send_all 函数体内**被显式识别。
        #
        # 判据必须限定在函数体内。早先写成 `re.search("EAGAIN", proxy_clean)`
        # 全文搜索 —— 而 handleClient 的 recv 循环里也有 EWOULDBLOCK，
        # 于是把 kk_send_all 里那段整块删掉，门禁照样绿。
        # 这是典型的"判据太宽等于没判"。
        if func and body_end:
            fn_body = proxy_clean[body_start:body_end]
            has_eagain = re.search(r"errno\s*==\s*EAGAIN", fn_body) and \
                         re.search(r"errno\s*==\s*EWOULDBLOCK", fn_body)
            if has_eagain:
                ok("kk_send_all 内部显式处理 EAGAIN/EWOULDBLOCK")
            else:
                fail("kk_send_all 内部没有识别 EAGAIN —— 电视快进时 send 超时会被当成断开")
        else:
            fail("无法定位 kk_send_all 函数体，EAGAIN 检查未生效")

        # (3) sendWholeResponse 不得自己 close。
        #
        # 关连接的责任必须只有一处（closeClientOnce），否则同一 fd
        # 会被关两次。第一次 close 后 fd 号立刻被系统复用给新连接，
        # 第二次 close 就把别人的连接关掉 —— 电视快进时会并发发起
        # 新请求，正好踩中，表现为"快进一下就再也连不上"。
        #
        # ★ 正则必须区分**声明**和**实现**。
        #   `- (void)sendWholeResponse:` 在 @interface 里也出现一次
        #   （以 `;` 结尾）。早先只用方法名搜索，命中的是声明，
        #   随后 index("{") 落到后面 +shared 的函数体上 ——
        #   判据一直在检查错误的方法，永远绿。
        #   用 `[^;{]*\{` 要求签名后直接跟 `{`，才是实现。
        m_whole = re.search(r"-\s*\(void\)\s*sendWholeResponse:[^;{]*\{", proxy_clean)
        if not m_whole:
            fail("找不到 sendWholeResponse: 的实现体（只找到声明？）")
        else:
            ob = m_whole.end() - 1
            depth = 0
            oe = None
            for i in range(ob, len(proxy_clean)):
                if proxy_clean[i] == "{":
                    depth += 1
                elif proxy_clean[i] == "}":
                    depth -= 1
                    if depth == 0:
                        oe = i
                        break
            body = proxy_clean[ob:oe] if oe else ""
            if re.search(r"\bclose\s*\(", body):
                fail("sendWholeResponse 内部自己 close —— 与 closeClientOnce 重复关同一 fd")
            else:
                ok("sendWholeResponse 不自行 close（收口到 closeClientOnce）")

            # (4) closeClientOnce 必须真的被调用过，否则上面的收口没有意义
        if re.search(r"\[\s*self\s+closeClientOnce\s*\]", proxy_clean):
            n_calls = len(re.findall(r"\[\s*self\s+closeClientOnce\s*\]", proxy_clean))
            ok(f"closeClientOnce 有 {n_calls} 处调用点")
        else:
            fail("closeClientOnce 定义了但从未调用 —— 防重入等于没生效")

        # (5) accept 出来的 fd 必须单独设 SO_NOSIGPIPE。
        # 监听 fd 上的选项不会被 accept 的新 fd 继承；漏设则电视
        # 一断连 send 就触发 SIGPIPE，iOS 直接终止进程（无 crash log）。
        m_acc = re.search(r"accept\s*\(", proxy_clean)
        if m_acc:
            after = proxy_clean[m_acc.end():m_acc.end() + 4000]
            if re.search(r"setsockopt\s*\(\s*client\s*,\s*SOL_SOCKET\s*,\s*SO_NOSIGPIPE",
                         after):
                ok("accept 之后给新 fd 单独设了 SO_NOSIGPIPE")
            else:
                fail("accept 后没有给 client fd 设 SO_NOSIGPIPE —— 电视断连会 SIGPIPE 杀进程")
        else:
            fail("找不到 accept 调用")

        # (6) _streamers 的增删必须在同一把锁下。
        # add 无锁 + remove 用 @synchronized 等于没有锁，
        # NSMutableSet 并发读写会崩在 objc_msgSend / 哈希重排。
        add_locked = re.search(
            r"@synchronized\s*\(\s*self\s*\)\s*\{\s*\[\s*_streamers\s+addObject", proxy_clean)
        rem_locked = re.search(
            r"@synchronized\s*\(\s*self\s*\)\s*\{\s*\[\s*_streamers\s+removeObject", proxy_clean)
        if add_locked and rem_locked:
            ok("_streamers 的 add/remove 都在 @synchronized(self) 下")
        else:
            missing = []
            if not add_locked:
                missing.append("add")
            if not rem_locked:
                missing.append("remove")
            fail(f"_streamers 的 {missing} 没在 @synchronized(self) 下 —— 并发会崩")

        # (7) 重写播放列表时，token 必须优先用请求里带过来的，
        #     不能只靠 tokenForEntryByAddress 反查。
        #
        # 反查是按 host 前缀匹配登记表猜的：地址带会变的查询串
        # （签名 / 时间戳 / 防盗链 token）时猜空，rewritePlaylist
        # 于是原样返回未重写的列表，电视按列表里的原始地址直连分片，
        # 遇防盗链直接卡住 —— 表现就是"拖进度条后进度不动"。
        # 请求路径 /p/<token>/... 里本来就带 token，是权威来源。
        m_flush = re.search(
            r"-\s*\(void\)\s*flushPlaylistWithCode:[^;{]*\{", proxy_clean)
        if not m_flush:
            fail("找不到 flushPlaylistWithCode: 的实现体")
        else:
            fb = m_flush.end() - 1
            depth = 0
            fe = None
            for i in range(fb, len(proxy_clean)):
                if proxy_clean[i] == "{":
                    depth += 1
                elif proxy_clean[i] == "}":
                    depth -= 1
                    if depth == 0:
                        fe = i
                        break
            fbody = proxy_clean[fb:fe] if fe else ""
            if re.search(r"self\s*\.\s*token", fbody):
                ok("flushPlaylistWithCode 使用请求自带的 token")
            else:
                fail("flushPlaylistWithCode 只靠反查 token —— 地址带签名时会重写失败并卡流")

        # (8) rewritePlaylist 在 token 为空时不得原样返回原文。
        # 原样返回 = 把未重写的列表当成功交付，等于把错误数据发给电视。
        m_rw = re.search(r"-\s*\(NSString\s*\*\)\s*rewritePlaylist:[^;{]*\{", proxy_clean)
        if not m_rw:
            fail("找不到 rewritePlaylist:baseURL:token:port: 的实现体")
        else:
            rb = m_rw.end() - 1
            depth = 0
            re_ = None
            for i in range(rb, len(proxy_clean)):
                if proxy_clean[i] == "{":
                    depth += 1
                elif proxy_clean[i] == "}":
                    depth -= 1
                    if depth == 0:
                        re_ = i
                        break
            rbody = proxy_clean[rb:re_] if re_ else ""
            # 找第一处 return
            first_ret = re.search(r"\breturn\b[^;]*;", rbody)
            if first_ret and re.search(r"return\s+text\s*\?:", first_ret.group(0)):
                fail("rewritePlaylist 在 token 为空时原样返回原文 —— 电视会直连源站卡死")
            else:
                ok("rewritePlaylist 不会把未重写的列表当成功交付")

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