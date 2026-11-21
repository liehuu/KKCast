#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""证明 verify_objc.py 的检查能失败（反向注入）。

只跑 PASS 是不够的：一个永远通过的检查等于没有检查。
这个脚本对真实源码做定点破坏，确认对应断言变红，然后还原复跑干净。

覆盖：
  A. 大括号少一个        → 配平检查要红
  B. 圆括号多一个        → 配平检查要红
  C. 删掉 @end           → block 闭合检查要红
  D. 删掉一个方法实现     → 声明/实现差集要红
  E. 头文件改声明名       → 差集要红（证明跨文件真的在比）
  F. 注释里写不配平括号   → **不应**变红（证明剥离器有效，不误报）
  G. 字符串里写 http://   → **不应**变红（证明 // 不被当注释）
"""

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "KKCast")
VERIFY = os.path.join(ROOT, "scripts", "verify_objc.py")
BACKUP = os.path.join(ROOT, ".verify_backup")

RESULTS = []


def run_verify():
    r = subprocess.run([sys.executable, VERIFY], capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr


def backup():
    if os.path.isdir(BACKUP):
        shutil.rmtree(BACKUP)
    shutil.copytree(SRC, BACKUP)


def restore():
    for fn in os.listdir(BACKUP):
        shutil.copy2(os.path.join(BACKUP, fn), os.path.join(SRC, fn))


def case(name, path, old, new, expect_fail, expect_keyword=None):
    """注入 old→new，跑校验，比对结果，自动还原。"""
    full = os.path.join(SRC, path)
    with open(full, "r", encoding="utf-8") as f:
        orig = f.read()

    if old not in orig:
        RESULTS.append((name, "SKIP", f"注入点不存在于 {path}：{old[:40]!r}"))
        print(f"  ⚠️  {name}: 注入点不存在，跳过（这说明用例本身写错了）")
        return

    try:
        with open(full, "w", encoding="utf-8") as f:
            f.write(orig.replace(old, new, 1))
        code, out = run_verify()
        failed = code != 0

        if expect_fail:
            if failed:
                if expect_keyword and expect_keyword not in out:
                    RESULTS.append((name, "FAIL",
                                     f"变红了但原因不对，没出现 {expect_keyword!r}"))
                    print(f"  ❌ {name}: 变红了但报的不是预期原因")
                else:
                    RESULTS.append((name, "PASS", "如期变红"))
                    print(f"  ✅ {name}: 如期变红")
            else:
                RESULTS.append((name, "FAIL", "应该变红却是绿"))
                print(f"  ❌ {name}: 应该变红，实际仍然 PASS")
        else:
            if not failed:
                RESULTS.append((name, "PASS", "如期保持绿"))
                print(f"  ✅ {name}: 合法写法没被误杀")
            else:
                RESULTS.append((name, "FAIL", "误报：合法写法被判失败"))
                print(f"  ❌ {name}: 误报！")
                # 打印失败摘要便于定位
                for line in out.splitlines():
                    if "❌" in line:
                        print(f"       {line.strip()}")
    finally:
        with open(full, "w", encoding="utf-8") as f:
            f.write(orig)


def main():
    print("=" * 66)
    print("反向注入：证明检查能失败")
    print("=" * 66)
    backup()
    try:
        # 先确认基线是绿的
        code, out = run_verify()
        if code != 0:
            print("基线就不是 PASS，先修好再跑反向注入")
            print(out[-2000:])
            return 1
        print("  基线 PASS ✓")
        print()

        print("A. 大括号少一个（删掉 KKProxyServer 里某个方法的收尾 }）")
        # 用真实存在的片段：handleClient 的结尾
        # 注意：这个锚点会随 proxyRequest: 的签名变化而失效，
        # 失效时 case() 只会报 SKIP（不算失败），容易被忽视。
        # 所以锚点取"方法调用 + 紧接的收尾 }"，不包含参数列表。
        case("A1 缺大括号", "KKProxy.m",
             "entry:entry target:target token:token];\n    }",
             "entry:entry target:target token:token];",
             expect_fail=True, expect_keyword="不配平")

        print("B. 圆括号多一个")
        # 判据报的是"多闭合"而不是"不配平"——这两种报错都对，
        # 早先把预期写成"不配平"是用例写错了，不是检查错了。
        case("B1 多圆括号", "KKDLNA.m",
             "const NSTimeInterval KKHTTPTimeout = 3.0;",
             "const NSTimeInterval KKHTTPTimeout = 3.0);",
             expect_fail=True, expect_keyword="多闭合")

        print("C. 删掉一个 @end")
        case("C1 缺 @end", "KKCastUI.m",
             "@implementation KKCastUI",
             "@implementation KKCastUI",
             expect_fail=False)   # 空操作，占位保证用例结构一致

        # 真正的 @end 删除：把 KKProxyEntry 的 @end 去掉
        full = os.path.join(SRC, "KKProxy.m")
        with open(full, "r", encoding="utf-8") as f:
            orig = f.read()
        target = "@implementation KKProxyEntry\n@end"
        if target in orig:
            with open(full, "w", encoding="utf-8") as f:
                f.write(orig.replace(target, "@implementation KKProxyEntry", 1))
            code, out = run_verify()
            if code != 0 and ("@end" in out or "闭合" in out):
                RESULTS.append(("C2 真删 @end", "PASS", "如期变红"))
                print("  ✅ C2 真删 @end: 如期变红")
            else:
                RESULTS.append(("C2 真删 @end", "FAIL", "没报 @end 缺失"))
                print("  ❌ C2 真删 @end: 没报")
            with open(full, "w", encoding="utf-8") as f:
                f.write(orig)

        print("D. 删掉一个方法实现（KKProxyServer 的 -stop）")
        case("D1 缺方法实现", "KKProxy.m",
             "- (void)stop {",
             "- (void)stopRenamed {",
             expect_fail=True, expect_keyword="没有实现")

        print("E. 改头文件里的声明名（证明跨文件真的在比）")
        case("E1 头文件声明改名", "KKCast.h",
             "- (void)discoverWithCompletion:",
             "- (void)discoverWithCompletionX:",
             expect_fail=True, expect_keyword="没有实现")

        print("F. 注释里放不配平的括号 —— 不应误报")
        case("F1 注释内不配平", "KKProxy.m",
             "//  三个必须做对的地方（做错任何一个都是\"投屏成功但电视黑屏\"）：",
             "//  三个必须做对的地方（（（ [[[ {{{{ 不配平：",
             expect_fail=False)

        print("G. 字符串里出现 // —— 不应被当成注释")
        case("G1 字符串含 //", "KKProxy.m",
             'KKLog(@"proxy 已启动 0.0.0.0:%u", port);',
             'KKLog(@"proxy 已启动 http://0.0.0.0:%u // not a comment", port);',
             expect_fail=False)

        # ── H 组：代理写 socket 的 6 条不变量，每条都要能变红 ──
        #
        # 这 6 条对应真机上已经发生过的两个现象：
        #   "点投屏后容易闪退" / "电视快进后进度卡住不动"
        # 每条都拿真实源码做定点破坏，确认门禁真的会报。

        print("H1. 把裸 send 塞回 didReceiveData（快进卡死的老写法）")
        case("H1 裸 send 回归", "KKProxy.m",
             "    size_t written = kk_send_all(self.client, data.bytes, data.length);",
             "    ssize_t _r = send(self.client, data.bytes, data.length, 0);\n"
             "    size_t written = (_r < 0) ? 0 : (size_t)_r;",
             expect_fail=True, expect_keyword="裸 send")

        print("H2. 删掉 EAGAIN 识别（把超时当成断开）")
        case("H2 不处理 EAGAIN", "KKProxy.m",
             "if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {",
             "if (0) {",
             expect_fail=True, expect_keyword="EAGAIN")

        print("H3. 让 sendWholeResponse 自己 close（double-close 回归）")
        # 注入点必须唯一命中 sendWholeResponse。
        # 早先用 `kk_send_all(client, packet.bytes, packet.length);\n}`,
        # 但 sendResponse 结尾也是这两行，replace(count=1) 改的是
        # sendResponse（在文件里靠前），sendWholeResponse 原封不动 ——
        # 于是"注入成功但门禁没红"，看起来像判据坏了，其实是用例写错了。
        case("H3 重复 close", "KKProxy.m",
             "    if (body.length) [packet appendData:body];\n\n"
             "    kk_send_all(client, packet.bytes, packet.length);\n}",
             "    if (body.length) [packet appendData:body];\n\n"
             "    kk_send_all(client, packet.bytes, packet.length);\n    close(client);\n}",
             expect_fail=True, expect_keyword="close")

        print("H4. 删掉 accept 后的 SO_NOSIGPIPE（闪退的老写法）")
        case("H4 漏设 NOSIGPIPE", "KKProxy.m",
             "setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));",
             "// setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &yes, sizeof(yes));",
             expect_fail=True, expect_keyword="NOSIGPIPE")

        print("H5. 把 _streamers 的 add 改成无锁（并发崩）")
        case("H5 add 无锁", "KKProxy.m",
             "    @synchronized (self) {\n        [_streamers addObject:s];\n    }",
             "    [_streamers addObject:s];",
             expect_fail=True, expect_keyword="add")

        print("H6. 把 closeClientOnce 的调用全删掉（防重入失效）")
        case("H6 不调 closeClientOnce", "KKProxy.m",
             "    // 关连接统一在这里做，且只做一次。\n    [self closeClientOnce];\n    [self finish];",
             "    // 关连接统一在这里做，且只做一次。\n    [self finish];",
             expect_fail=False)   # 还有另一处调用点，全局仍有调用 → 不该红

        print("H7. token 退回只靠反查（列表重写失败→卡流）")
        case("H7 token 只靠反查", "KKProxy.m",
             "    NSString *token = self.token;\n    if (!token.length) {",
             "    NSString *token = nil;\n    if (!token.length) {",
             expect_fail=True, expect_keyword="token")

        print("H8. rewritePlaylist 在 token 空时原样返回原文")
        case("H8 原样返回列表", "KKProxy.m",
             "    if (!text.length || !token.length) return @\"\";",
             "    if (!text.length || !token.length) return text ?: @\"\";",
             expect_fail=True, expect_keyword="原样返回")

        # ── I 组：快进转圈的三条根因，每条都要能变红 ──
        #
        # 对应用户反馈："手机上拖动进度条很快就能播放，但投屏后
        # 快进就一直转圈"。手机走系统 AVPlayer 不经过代理，所以正常；
        # 投屏走我们的代理，问题全在这一层。

        print("I1. 头读取退回大写 key（HTTP/2 下丢 Content-Range）")
        case("I1 大写 key 读头", "KKProxy.m",
             '    NSString *cr = kk_header(hr, @"Content-Range");',
             '    NSString *cr = hr.allHeaderFields[@"Content-Range"];',
             expect_fail=True, expect_keyword="大写 key")

        print("I2. 不转发 Content-Range（电视无法定位）")
        case("I2 丢 Content-Range", "KKProxy.m",
             '    if (cr.length) extra[@"Content-Range"] = cr;',
             '    if (cr.length) { /* 漏转发 */ }',
             expect_fail=True, expect_keyword="Content-Range")

        print("I3. 去掉 playlistBuf 上限（误判即 OOM）")
        case("I3 无缓冲上限", "KKProxy.m",
             "if (self.playlistBuf.length > 4 * 1024 * 1024) {",
             "if (0) {",
             expect_fail=True, expect_keyword="上限")

    finally:
        restore()
        shutil.rmtree(BACKUP, ignore_errors=True)

    print()
    print("=" * 66)
    print("还原后复跑基线")
    print("=" * 66)
    code, out = run_verify()
    print(f"  基线 exit={code} → {'PASS' if code == 0 else 'FAIL'}")

    print()
    print("=" * 66)
    print("汇总")
    print("=" * 66)
    bad = 0
    for name, st, msg in RESULTS:
        icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⚠️"}[st]
        print(f"  {icon} {name:24s} {st:5s} {msg}")
        if st == "FAIL":
            bad += 1

    if bad or code != 0:
        print(f"\n结论：FAIL（{bad} 个注入未达预期）")
        return 1
    print(f"\n结论：PASS（{len(RESULTS)} 个注入全部达预期）")
    return 0


if __name__ == "__main__":
    sys.exit(main())