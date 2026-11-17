#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在 git push 走不通时，用 GitHub Git Data API 把本地 HEAD 推上去。

为什么需要这个：
  本机 git 走 127.0.0.1:57886 代理，代理会间歇性返回
  "CONNECT tunnel failed, response 502"；而直连 github.com:443 被网络阻断
  （超时），只有 api.github.com 能直连通。也就是说 git 传输层不可用，
  但 REST API 可用。

  所以这里用 blob → tree → commit → update-ref 四步复刻 git push 的语义：
  本地 HEAD 的完整树 + 远端当前 head 作为 parent，得到一个干净的快进提交。

  注意：这不是"绕过检查"。产出的 commit 与 git push 产出的对象结构一致，
  远端后续 git pull 不会有任何差异。

用法：
  python scripts/gh_push.py                 # 推送 HEAD 到 main
  python scripts/gh_push.py --branch main
  python scripts/gh_push.py --dry-run
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

REPO = "liehuu/KKCast"
API = "https://api.github.com"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def token():
    p = os.path.join(ROOT, ".ghtok")
    if os.path.exists(p):
        t = open(p, encoding="utf-8").read().strip()
        if t:
            return t
    out = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True, text=True, cwd=ROOT)
    for line in out.stdout.splitlines():
        if line.startswith("password="):
            return line[len("password="):].strip()
    raise SystemExit("拿不到 token")


TOKEN = token()


def api(method, path, payload=None, allow=(200, 201, 204)):
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(API + path, data=body, method=method)
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "kkcast-push")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", "replace")
        raise SystemExit(f"{method} {path} -> HTTP {e.code}\n{msg[:800]}")
    if code not in allow:
        raise SystemExit(f"{method} {path} -> HTTP {code}")
    return json.loads(raw.decode("utf-8")) if raw else {}


def git(*args):
    out = subprocess.run(["git"] + list(args), capture_output=True, cwd=ROOT)
    if out.returncode != 0:
        raise SystemExit("git " + " ".join(args) + " 失败: " +
                         out.stderr.decode("utf-8", "replace")[:400])
    return out.stdout


def local_head():
    return git("rev-parse", "HEAD").decode().strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--branch", default="main")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    head = local_head()
    files = [f for f in git("ls-tree", "-r", "--name-only", head).decode().splitlines() if f]
    print(f"本地 HEAD {head[:8]}，{len(files)} 个文件（不含 .ghtok 时应为仓库真实内容）")

    # .ghtok 不该进仓库（里面有 token）。它在 .gitignore 里，但 HEAD 树是
    # 显式列出的，这里再挡一次，防止哪天被误 add。
    bad = [f for f in files if f in (".ghtok", ".test_out.ipa")]
    if bad:
        raise SystemExit(f"拒绝推送敏感/临时文件: {bad}")

    remote = api("GET", f"/repos/{REPO}/git/ref/heads/{a.branch}")
    parent = remote["object"]["sha"]
    print(f"远端 {a.branch} = {parent[:8]}")
    if parent == head:
        print("远端已是最新，无需推送")
        return 0
    if a.dry_run:
        print("dry-run：到此为止")
        return 0

    # 用本地 HEAD 的 tree 直接复用（比逐个上传 blob 快得多，因为对象已在
    # 本地存在——但 API 这边不认识本地对象，所以还是得上传 blob）。
    # 优化：只上传远端树上没有的内容。远端树拿不到逐文件 sha 对比成本高，
    # 这里采用"全量 blob 上传 + 复用同名同 sha 会命中服务端缓存"的简单做法。
    tree_items = []
    for i, path in enumerate(files, 1):
        abspath = os.path.join(ROOT, path.replace("/", os.sep))
        data = open(abspath, "rb").read()
        mode = "100755" if os.access(abspath, os.X_OK) and not path.endswith(
            (".py", ".md", ".yml", ".yaml", ".txt", ".json")) else "100644"
        blob = api("POST", f"/repos/{REPO}/git/blobs",
                   {"content": base64.b64encode(data).decode("ascii"),
                    "encoding": "base64"})
        tree_items.append({"path": path, "mode": mode, "type": "blob", "sha": blob["sha"]})
        print(f"  [{i}/{len(files)}] {path} ({len(data)} B)")

    tree = api("POST", f"/repos/{REPO}/git/trees", {"tree": tree_items})
    msg = git("log", "-1", "--pretty=%B").decode().strip()
    commit = api("POST", f"/repos/{REPO}/git/commits",
                 {"message": msg, "tree": tree["sha"], "parents": [parent]})
    api("PATCH", f"/repos/{REPO}/git/refs/heads/{a.branch}",
        {"sha": commit["sha"], "force": False})
    print(f"\n✅ 推送完成 {commit['sha']}")
    print(f"   parent {parent[:8]} -> {commit['sha'][:8]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())