#!/usr/bin/env python3
"""Crawl NSSCTF REVERSE problems with level 3-4: content, annex, writeups."""

from __future__ import annotations

import json
import os
import re
import ssl
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "nssctf_reverse_l3_4"
LIST_JSON = ROOT / "nssctf_reverse_problems.json"

COOKIE = (
    "Hm_lvt_648a44a949074de73151ffaa0a832aec=1784384572; "
    "Hm_lpvt_648a44a949074de73151ffaa0a832aec=1784384572; "
    "HMACCOUNT=FA98968BF9D8E73C; "
    "sessionid=qsnb4gswaizshl4yonhh1c26ole5vt1d; "
    "token=2f6325e86337424abd73db70114b531d; "
    "rtoken=GSBP0|1784989380|913e404a243a2cf75b4c120a526d60f4|6975355c79084775"
)
UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
CTX = ssl.create_default_context()
TARGET = 150
MAX_WP_PER_PROBLEM = 3
SLEEP = 0.2

# files.nssctf.cn blocks overseas proxy egress with HTTP 514.
# Force direct connections for API + file CDN.
os.environ["NO_PROXY"] = "*"
os.environ["no_proxy"] = "*"
for k in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
    os.environ.pop(k, None)

NO_PROXY_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=CTX),
)

def sanitize(name: str, max_len: int = 80) -> str:
    name = re.sub(r'[\\/:*?"<>|\n\r\t]+', "_", name).strip(" ._")
    return (name or "untitled")[:max_len]


class Client:
    def __init__(self) -> None:
        self.session_cookie_parts = {
            x.split("=", 1)[0]: x.split("=", 1)[1]
            for x in COOKIE.split("; ")
            if "=" in x
        }

    def _headers(self, referer: str = "https://www.nssctf.cn/problem", binary: bool = False):
        headers = {
            "User-Agent": UA,
            "Cookie": "; ".join(f"{k}={v}" for k, v in self.session_cookie_parts.items()),
            "Accept": "*/*" if binary else "application/json, text/plain, */*",
            "Referer": referer,
            "Origin": "https://www.nssctf.cn",
        }
        if not binary:
            headers["Content-Type"] = "application/json"
        return headers

    def request(
        self,
        method: str,
        url: str,
        body=None,
        timeout: int = 60,
        binary: bool = False,
        referer: str | None = None,
    ):
        data = None if body is None else json.dumps(body).encode()
        headers = self._headers(referer or "https://www.nssctf.cn/problem", binary=binary)
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        last = None
        for attempt in range(4):
            try:
                with NO_PROXY_OPENER.open(req, timeout=timeout) as resp:
                    raw = resp.read()
                    for c in resp.headers.get_all("Set-Cookie") or []:
                        m = re.match(r"([^=]+)=([^;]+)", c)
                        if m:
                            self.session_cookie_parts[m.group(1)] = m.group(2)
                    if binary:
                        return resp.status, dict(resp.headers), raw
                    try:
                        return resp.status, json.loads(raw.decode("utf-8", "replace"))
                    except Exception:
                        return resp.status, raw
            except urllib.error.HTTPError as e:
                raw = e.read()
                if binary:
                    return e.code, dict(e.headers), raw
                try:
                    return e.code, json.loads(raw.decode("utf-8", "replace"))
                except Exception:
                    return e.code, raw
            except Exception as e:
                last = e
                time.sleep(1.2 * (attempt + 1))
        raise RuntimeError(f"request failed {method} {url}: {last}")

    def api(self, method: str, path: str, body=None, timeout: int = 60, referer: str | None = None):
        return self.request(
            method,
            "https://www.nssctf.cn/api" + path,
            body=body,
            timeout=timeout,
            referer=referer,
        )


def extract_filename(url: str, headers=None, default: str = "annex.bin") -> str:
    m = re.search(r"filename\*?=(?:UTF-8''|UTF-8')?\"?([^\";]+)\"?", url, re.I)
    if m:
        return unquote(m.group(1))
    if headers:
        cd = headers.get("Content-Disposition") or headers.get("content-disposition") or ""
        m = re.search(r"filename\*?=(?:UTF-8''|UTF-8')?\"?([^\";]+)\"?", cd, re.I)
        if m:
            return unquote(m.group(1))
    base = os.path.basename(urlparse(url).path)
    return base or default


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "problems").mkdir(exist_ok=True)

    cli = Client()
    code, info = cli.api("GET", "/user/info/")
    print("login", code, info.get("code") if isinstance(info, dict) else info, flush=True)
    if isinstance(info, dict) and info.get("code") == 200:
        print(
            "user",
            info["data"].get("username"),
            "vip",
            info["data"].get("vip"),
            flush=True,
        )
        if info["data"].get("token"):
            cli.session_cookie_parts["token"] = info["data"]["token"]

    allp = json.loads(LIST_JSON.read_text(encoding="utf-8"))["problems"]
    cands = [
        p
        for p in allp
        if p.get("level") is not None and 3.0 <= float(p["level"]) <= 4.0
    ]

    def score(p):
        info_ = p.get("info") or {}
        return (
            1 if p.get("wp") else 0,
            info_.get("solved") or 0,
            -abs(float(p.get("level") or 0) - 3.5),
            -(p.get("point") or 0),
        )

    cands = sorted(cands, key=score, reverse=True)
    print(f"candidates level 3-4: {len(cands)}", flush=True)

    progress_path = OUT / "progress.json"
    if progress_path.exists():
        progress = json.loads(progress_path.read_text(encoding="utf-8"))
    else:
        progress = {"done_ids": [], "failed": [], "skipped": [], "stats": {}}
    done = set(progress.get("done_ids") or [])

    def save_progress() -> None:
        progress_path.write_text(json.dumps(progress, ensure_ascii=False, indent=2), encoding="utf-8")

    def fetch_wp_list(pid: int):
        wps = []
        page = 1
        while page <= 5 and len(wps) < MAX_WP_PER_PROBLEM:
            _, data = cli.api(
                "GET",
                f"/problem/v2/{pid}/wp/{page}/",
                referer=f"https://www.nssctf.cn/problem/{pid}",
            )
            if not isinstance(data, dict) or data.get("code") != 200:
                break
            batch = data.get("data") or []
            if not batch:
                break
            for item in batch:
                if item not in wps:
                    wps.append(item)
                if len(wps) >= MAX_WP_PER_PROBLEM:
                    break
            if len(batch) < 10:
                break
            page += 1
            time.sleep(SLEEP)
        return wps

    def fetch_article(nid: int):
        _, data = cli.api("GET", f"/notebook/article/{nid}")
        if isinstance(data, dict) and data.get("code") == 200:
            return data["data"]
        return None

    def open_problem(pid: int):
        _, data = cli.api(
            "POST",
            f"/problem/docker/{pid}/open/",
            {"type": 0},
            referer=f"https://www.nssctf.cn/problem/{pid}",
        )
        return data if isinstance(data, dict) else {"code": None, "data": data}

    def close_problem(pid: int) -> None:
        try:
            cli.api(
                "POST",
                f"/problem/docker/{pid}/close/",
                referer=f"https://www.nssctf.cn/problem/{pid}",
            )
        except Exception:
            pass

    def download_annex(pid: int, dest_dir: Path):
        _, data = cli.api(
            "GET",
            f"/problem/{pid}/annex/download/",
            referer=f"https://www.nssctf.cn/problem/{pid}",
        )
        if not isinstance(data, dict):
            return {"ok": False, "error": f"bad response"}
        if data.get("code") != 200 or not data.get("data"):
            return {"ok": False, "error": f"annex code={data.get('code')}", "raw": data}
        url = data["data"]
        status, headers, raw = cli.request("GET", url, binary=True, timeout=180)
        if status != 200 or not raw:
            return {"ok": False, "error": f"download http {status}", "url": url}
        fname = sanitize(extract_filename(url, headers), 120) or "annex.bin"
        path = dest_dir / fname
        if path.exists():
            stem, suf = path.stem, path.suffix
            i = 1
            while path.exists():
                path = dest_dir / f"{stem}_{i}{suf}"
                i += 1
        path.write_bytes(raw)
        return {
            "ok": True,
            "url": url,
            "file": str(path.relative_to(OUT)),
            "size": len(raw),
            "filename": path.name,
        }

    def ensure_annex_for_existing(folder: Path, pid: int, rec: dict) -> dict:
        annex_dir = folder / "annex"
        annex_dir.mkdir(exist_ok=True)
        existing = [p for p in annex_dir.iterdir() if p.is_file() and p.stat().st_size > 0]
        if existing:
            p = existing[0]
            return {
                "ok": True,
                "file": str(p.relative_to(OUT)),
                "size": p.stat().st_size,
                "filename": p.name,
                "cached": True,
            }
        # open + download + close
        od = open_problem(pid)
        if od.get("code") != 200:
            return {"ok": False, "error": f"open_failed", "open": od}
        time.sleep(SLEEP)
        result = download_annex(pid, annex_dir)
        close_problem(pid)
        return result

    opened_count = 0
    annex_ok = 0
    wp_ok = 0
    coin_fail = 0
    errors = 0

    # First pass: repair annex for already-done problems
    print("=== repair missing annex for existing problems ===", flush=True)
    for d in sorted((OUT / "problems").iterdir()):
        if not d.is_dir():
            continue
        m = re.match(r"^(\d+)_", d.name)
        if not m:
            continue
        pid = int(m.group(1))
        st_path = d / "crawl_status.json"
        rec = json.loads(st_path.read_text(encoding="utf-8")) if st_path.exists() else {
            "pid": pid,
            "title": d.name,
            "folder": str(d.relative_to(OUT)),
            "errors": [],
        }
        annex = rec.get("annex") or {}
        has_file = any(
            p.is_file() and p.stat().st_size > 0 for p in (d / "annex").glob("*")
        ) if (d / "annex").exists() else False
        if annex.get("ok") and has_file:
            annex_ok += 1
            continue
        print(f"repair annex pid={pid}", flush=True)
        try:
            result = ensure_annex_for_existing(d, pid, rec)
            rec["annex"] = result
            if result.get("ok"):
                annex_ok += 1
                opened_count += 1
                print(f"  OK {result.get('filename')} size={result.get('size')}", flush=True)
            else:
                rec.setdefault("errors", []).append(f"annex_repair: {result}")
                print(f"  FAIL {result}", flush=True)
            st_path.write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
            time.sleep(SLEEP)
        except Exception as e:
            print(f"  EXC {e}", flush=True)
            traceback.print_exc()

    # Second pass: crawl until TARGET
    todo = [p for p in cands if p["id"] not in done]
    print(f"already done {len(done)}, todo pool {len(todo)}, target {TARGET}", flush=True)

    for base in todo:
        if len(done) >= TARGET:
            break
        pid = base["id"]
        title = base.get("title") or f"problem_{pid}"
        folder = OUT / "problems" / f"{pid}_{sanitize(title)}"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "annex").mkdir(exist_ok=True)
        (folder / "wp").mkdir(exist_ok=True)

        rec = {
            "pid": pid,
            "title": title,
            "level": base.get("level"),
            "point": base.get("point"),
            "status": "ok",
            "folder": str(folder.relative_to(OUT)),
            "annex": None,
            "wp_count": 0,
            "errors": [],
        }
        print(
            f"\n[{len(done)+1}/{TARGET}] pid={pid} lv={base.get('level')} pt={base.get('point')} {title}",
            flush=True,
        )
        try:
            _, detail = cli.api(
                "GET",
                f"/problem/v2/{pid}/",
                referer=f"https://www.nssctf.cn/problem/{pid}",
            )
            if not isinstance(detail, dict) or detail.get("code") != 200:
                rec["status"] = "detail_fail"
                rec["errors"].append(f"detail {detail}")
                progress.setdefault("failed", []).append(rec)
                errors += 1
                save_progress()
                continue
            pdata = detail["data"]
            (folder / "meta.json").write_text(
                json.dumps(pdata, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            tags = ", ".join(
                t[0] if isinstance(t, list) else str(t) for t in (pdata.get("tag") or [])
            )
            (folder / "description.md").write_text(
                f"# {pdata.get('title')}\n\n"
                f"- id: {pid}\n- level: {pdata.get('level')}\n- point: {pdata.get('point')}\n"
                f"- tags: {tags}\n- url: https://www.nssctf.cn/problem/{pid}\n\n"
                f"## 题目描述\n\n{pdata.get('desc') or ''}\n",
                encoding="utf-8",
            )
            time.sleep(SLEEP)

            annex_result = {"ok": False, "skipped": True, "reason": "no annex"}
            if pdata.get("annex"):
                need_open = not pdata.get("is_open")
                if need_open:
                    od = open_problem(pid)
                    if od.get("code") == 200:
                        opened_count += 1
                        pdata["is_open"] = True
                    elif od.get("code") == 202:
                        coin_fail += 1
                        rec["errors"].append("open coin insufficient")
                        annex_result = {"ok": False, "error": "coin_insufficient", "open": od}
                    else:
                        rec["errors"].append(f"open failed {od}")
                        annex_result = {"ok": False, "error": "open_failed", "open": od}
                    time.sleep(SLEEP)
                if pdata.get("is_open"):
                    annex_result = download_annex(pid, folder / "annex")
                    if annex_result.get("ok"):
                        annex_ok += 1
                    else:
                        rec["errors"].append(f"annex: {annex_result}")
                    if need_open:
                        close_problem(pid)
                        time.sleep(SLEEP)
            rec["annex"] = annex_result
            time.sleep(SLEEP)

            wp_meta = []
            _, off = cli.api(
                "GET",
                f"/problem/{pid}/wp/official/",
                referer=f"https://www.nssctf.cn/problem/{pid}",
            )
            if isinstance(off, dict) and off.get("code") == 200 and off.get("data"):
                content = off["data"].get("content") or ""
                aid = off["data"].get("aid") or off["data"].get("id") or "official"
                fn = folder / "wp" / f"official_{aid}.md"
                author = (off["data"].get("author") or {}).get("username") or "official"
                fn.write_text(
                    f"# {off['data'].get('title') or '官方题解'}\n\n"
                    f"- author: {author}\n- source: official\n\n{content}\n",
                    encoding="utf-8",
                )
                wp_meta.append(
                    {
                        "type": "official",
                        "id": aid,
                        "title": off["data"].get("title"),
                        "file": str(fn.relative_to(folder)),
                    }
                )
                wp_ok += 1
            time.sleep(SLEEP)

            wplist = fetch_wp_list(pid)
            (folder / "wp" / "list.json").write_text(
                json.dumps(wplist, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            for item in wplist:
                nid = item.get("nid") or item.get("id")
                if not nid:
                    continue
                if any(w.get("id") == nid for w in wp_meta):
                    continue
                art = fetch_article(nid)
                time.sleep(SLEEP)
                if not art:
                    rec["errors"].append(f"wp article {nid} fail")
                    continue
                title_wp = sanitize(art.get("title") or f"wp_{nid}")
                fn = folder / "wp" / f"{nid}_{title_wp}.md"
                fn.write_text(
                    f"# {art.get('title')}\n\n"
                    f"- author: {art.get('author')}\n- nid: {nid}\n"
                    f"- tags: {', '.join(art.get('tag') or [])}\n\n"
                    f"{art.get('content') or ''}\n",
                    encoding="utf-8",
                )
                (folder / "wp" / f"{nid}.json").write_text(
                    json.dumps(art, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                wp_meta.append(
                    {
                        "type": "community",
                        "id": nid,
                        "title": art.get("title"),
                        "file": str(fn.relative_to(folder)),
                    }
                )
                wp_ok += 1

            rec["wp_count"] = len(wp_meta)
            (folder / "wp_index.json").write_text(
                json.dumps(wp_meta, ensure_ascii=False, indent=2), encoding="utf-8"
            )
            (folder / "crawl_status.json").write_text(
                json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8"
            )

            done.add(pid)
            progress["done_ids"] = list(done)
            progress["stats"] = {
                "done": len(done),
                "annex_ok": annex_ok,
                "wp_ok": wp_ok,
                "opened": opened_count,
                "coin_fail": coin_fail,
                "errors": errors,
            }
            save_progress()
            print(
                f"  annex={rec['annex'].get('ok')} wp={rec['wp_count']} errs={len(rec['errors'])}",
                flush=True,
            )
        except Exception as e:
            rec["status"] = "exception"
            rec["errors"].append(str(e))
            progress.setdefault("failed", []).append(rec)
            errors += 1
            save_progress()
            print("  EXCEPTION", e, flush=True)
            traceback.print_exc()
            time.sleep(1)

    # rebuild index
    disk_results = []
    for d in sorted((OUT / "problems").iterdir()):
        if not d.is_dir():
            continue
        st = d / "crawl_status.json"
        if st.exists():
            disk_results.append(json.loads(st.read_text(encoding="utf-8")))
        else:
            m = re.match(r"^(\d+)_", d.name)
            disk_results.append(
                {
                    "pid": int(m.group(1)) if m else None,
                    "folder": str(d.relative_to(OUT)),
                }
            )

    annex_files = 0
    for r in disk_results:
        a = r.get("annex") or {}
        if a.get("ok"):
            annex_files += 1
        else:
            folder = OUT / (r.get("folder") or "")
            if folder.exists() and any(
                p.is_file() and p.stat().st_size > 0 for p in (folder / "annex").glob("*")
            ):
                annex_files += 1

    index = {
        "target": TARGET,
        "completed": len(disk_results),
        "level_range": [3.0, 4.0],
        "category": "REVERSE",
        "stats": {
            "done": len(disk_results),
            "annex_ok": annex_files,
            "wp_ok": wp_ok,
            "opened": opened_count,
            "coin_fail": coin_fail,
            "errors": errors,
        },
        "problems": disk_results,
    }
    (OUT / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    lines = [
        "# NSSCTF Reverse Level 3-4 爬取结果",
        "",
        f"- 目标数量: {TARGET}",
        f"- 完成数量: {len(disk_results)}",
        f"- 附件成功: {annex_files}",
        f"- WP 文档数(本轮累计增量统计): {wp_ok}",
        f"- 开启环境次数: {opened_count}",
        f"- 金币不足次数: {coin_fail}",
        "",
        "| # | PID | Level | Point | Title | Annex | WP |",
        "|---:|---:|---:|---:|---|---|---:|",
    ]
    for i, r in enumerate(disk_results, 1):
        annex = r.get("annex") or {}
        aok = "Y" if annex.get("ok") else "N"
        folder = OUT / (r.get("folder") or "")
        if folder.exists() and any(
            p.is_file() and p.stat().st_size > 0 for p in (folder / "annex").glob("*")
        ):
            aok = "Y"
        lines.append(
            f"| {i} | {r.get('pid')} | {r.get('level')} | {r.get('point')} | "
            f"{r.get('title', '')} | {aok} | {r.get('wp_count', 0)} |"
        )
    (OUT / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    progress["stats"] = index["stats"]
    progress["done_ids"] = [r.get("pid") for r in disk_results if r.get("pid")]
    save_progress()
    print("\n==== DONE ====", flush=True)
    print(
        "completed",
        len(disk_results),
        "annex_ok",
        annex_files,
        "wp_ok",
        wp_ok,
        "coin_fail",
        coin_fail,
        "errors",
        errors,
        flush=True,
    )
    print("out", OUT, flush=True)


if __name__ == "__main__":
    main()
