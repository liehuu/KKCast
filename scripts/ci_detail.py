#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""拉取某个 run 的详细诊断：run 级别字段、job 的 steps、失败步骤日志尾部。"""
import json
import os
import sys
import urllib.request

REPO = "liehuu/KKCast"
_HERE = os.path.dirname(os.path.abspath(__file__))
TOKEN = open(os.path.join(_HERE, "..", ".ghtok"), encoding="utf-8").read().strip()
API = "https://api.github.com"


def call(path, raw=False, accept=None):
    req = urllib.request.Request(API + path)
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Accept", accept or "application/vnd.github+json")
    req.add_header("User-Agent", "kkcast-ci")
    with urllib.request.urlopen(req, timeout=90) as r:
        body = r.read()
    return body if raw else json.loads(body.decode("utf-8"))


def main():
    rid = sys.argv[1] if len(sys.argv) > 1 else None
    if rid is None:
        runs = call(f"/repos/{REPO}/actions/runs?per_page=1")["workflow_runs"]
        rid = runs[0]["id"]

    r = call(f"/repos/{REPO}/actions/runs/{rid}")
    for k in ("id", "name", "display_title", "event", "status", "conclusion",
              "run_attempt", "created_at", "updated_at", "head_sha",
              "run_started_at", "html_url"):
        print(f"{k:<16} {r.get(k)}")
    print()

    jobs = call(f"/repos/{REPO}/actions/runs/{rid}/jobs")
    print(f"jobs total_count = {jobs.get('total_count')}")
    for j in jobs.get("jobs", []):
        print(f"\njob: {j['name']}  status={j['status']} conclusion={j['conclusion']}")
        print(f"  started={j.get('started_at')} completed={j.get('completed_at')}")
        print(f"  runner={j.get('runner_name')} labels={j.get('labels')}")
        steps = j.get("steps", [])
        print(f"  steps={len(steps)}")
        for s in steps:
            print(f"   [{s['number']:>2}] {s['status']:<10} {str(s['conclusion']):<10} {s['name']}")
        if not steps:
            print("  ⚠️ 零步骤：job 从未在 runner 上开始执行。")
    return 0


if __name__ == "__main__":
    sys.exit(main())