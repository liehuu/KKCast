#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""下载某个 run 的 artifact 到本地 dist-ci/ 并解包。

GitHub 的 job logs 端点需要 repo admin 权限，公开仓库的 Actions 日志
走 API 会返回 401；artifact 端点则只要普通读权限，所以这里走 artifact
拿 build.log。
"""
import io
import json
import os
import sys
import urllib.error
import urllib.request
import zipfile

REPO = "liehuu/KKCast"
API = "https://api.github.com"
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOKEN = open(os.path.join(ROOT, ".ghtok"), encoding="utf-8").read().strip()


def get(path, follow_ok=True):
    req = urllib.request.Request(API + path)
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("User-Agent", "kkcast")
    req.add_header("Accept", "application/vnd.github+json")
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read()


def raw_get(url):
    """artifact 的 download 端点需要 Bearer，但它返回 302 到
    objects.githubusercontent.com，那个域名带签名、**不能**带 Authorization
    （带了会 401 或 403）。所以两段式：带 auth 拿跳转地址，不带 auth 取内容。"""
    req = urllib.request.Request(url)
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("User-Agent", "kkcast")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    loc = None
    try:
        with opener.open(req, timeout=300) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        if e.code in (301, 302, 303, 307, 308):
            loc = e.headers.get("Location")
        else:
            raise SystemExit("artifact 下载失败 HTTP %d: %s"
                             % (e.code, e.read()[:200]))
    if not loc:
        raise SystemExit("没有拿到跳转地址")
    req2 = urllib.request.Request(loc)
    req2.add_header("User-Agent", "kkcast")
    with urllib.request.urlopen(req2, timeout=300) as r:
        return r.read()


def main():
    rid = sys.argv[1] if len(sys.argv) > 1 else None
    if not rid:
        runs = json.loads(get("/repos/%s/actions/runs?per_page=1" % REPO))
        rid = runs["workflow_runs"][0]["id"]
    arts = json.loads(get("/repos/%s/actions/runs/%s/artifacts" % (REPO, rid)))
    items = arts.get("artifacts", [])
    print("run %s: %d artifacts" % (rid, len(items)))
    outdir = os.path.join(ROOT, "dist-ci")
    os.makedirs(outdir, exist_ok=True)
    for a in items:
        print("  %s (%d B, expired=%s)" % (a["name"], a["size_in_bytes"], a["expired"]))
        if a["expired"]:
            continue
        data = raw_get(a["archive_download_url"])
        z = zipfile.ZipFile(io.BytesIO(data))
        for n in z.namelist():
            dst = os.path.join(outdir, n.replace("/", os.sep))
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(z.read(n))
            print("    -> %s (%d B)" % (n, os.path.getsize(dst)))
    return 0


if __name__ == "__main__":
    sys.exit(main())