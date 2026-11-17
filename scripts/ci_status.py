#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""查看 KKCast 仓库的 GitHub Actions 状态，必要时打印失败步骤的日志。

只做读操作。token 从 /tmp/ghtok.txt 读取（由 git credential fill 产出）。
"""
import json
import sys
import urllib.request

REPO = "liehuu/KKCast"
import os
_HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = open(os.path.join(_HERE, "..", ".ghtok"), encoding="utf-8").read().strip()
API = "https://api.github.com"


def call(path, raw=False):
    req = urllib.request.Request(API + path)
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "kkcast-ci")
    with urllib.request.urlopen(req, timeout=60) as r:
        body = r.read()
    if raw:
        return body
    return json.loads(body.decode("utf-8"))


def main():
    runs = call(f"/repos/{REPO}/actions/runs?per_page=5")
    items = runs.get("workflow_runs", [])
    if not items:
        print("还没有任何 workflow run（可能 push 未触发，或 Actions 未启用）")
        return 2
    for r in items:
        print(f"run #{r['run_number']} id={r['id']} status={r['status']} "
              f"conclusion={r['conclusion']} branch={r['head_branch']} "
              f"sha={r['head_sha'][:8]} created={r['created_at']}")
    cur = items[0]
    rid = cur["id"]
    jobs = call(f"/repos/{REPO}/actions/runs/{rid}/jobs")
    total = jobs.get("total_count", 0)
    print(f"\n--- run {rid} jobs total={total} ---")
    if total == 0:
        print("⚠️  total_count=0 —— 没有产生 job。这不是编译失败，")
        print("    通常是 workflow YAML 解析失败。先验 workflow 语法。")
        return 3
    for j in jobs["jobs"]:
        print(f"job {j['name']} status={j['status']} conclusion={j['conclusion']}")
        for s in j.get("steps", []):
            print(f"   [{s['number']:>2}] {s['status']:<10} {s['conclusion'] or '-':<10} {s['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())