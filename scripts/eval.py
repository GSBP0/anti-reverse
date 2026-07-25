"""评估 harness(§9.5 / §14 step 7):对测试集按题隔离 + 硬时间预算运行,对照 writeup 打分,汇总指标。

用法:
    conda run -n antirev python scripts/eval.py [--split train_set_1] [--budget 360] [--limit N] [--only PID,PID]
指标:解出率 / 平均步数 / 墙钟 / 失败卡点分布。结果增量写 logs/eval_<split>.jsonl。
"""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

from antirev import config
from antirev.tools.analyze_tools import file_info, ascii_strings

ROOT = config.PROJECT_ROOT
_SOLVABLE_KW = ("correct", "wrong", "right", "flag", "nssctf", "tea", "xtea", "rc4",
                "aes", "base64", "xor", "key", "input", "encrypt", "cipher")


def triage_score(binary) -> int:
    """§11 先打软柿子:估可解性(高分先跑)。有密码/成功失败线索、体积小、导入少 → 更可能可解。"""
    try:
        fi = file_info(binary)
        if fi["format"] not in ("PE", "ELF"):
            return -1
        blob = " ".join(ascii_strings(binary, 5, 400)).lower()
        s = sum(2 for kw in _SOLVABLE_KW if kw in blob)
        if fi.get("size", 10 ** 9) < 80_000:
            s += 3
        if fi.get("num_imports", 99) < 20:
            s += 1
        return s
    except Exception:
        return -1
FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,12}\{[^}]{1,120}\}")
# 明显不是 flag 的花括号内容(代码/占位),排除
_NOISE = ("void", "int ", "char ", "return", "if(", "for(", "printf", "struct", "0x")


def extract_flags(text: str) -> set:
    out = set()
    for m in FLAG_RE.finditer(text):
        s = m.group(0)
        if any(n in s for n in _NOISE):
            continue
        out.add(s)
    return out


def ground_truth(problem_dir: Path) -> set:
    # 优先权威 truth 库(data/flags_truth.json,从公开 wp 搜集); 缺则回退题库自带 wp/*.md
    pid = problem_dir.name.split("_")[0]
    from antirev.flag_check import load_truth, _truths_for
    entry = load_truth().get(pid)
    if entry:
        return set(_truths_for(entry))
    flags = set()
    for wp in list(problem_dir.glob("wp/*.md")) + list(problem_dir.glob("wp/*.txt")):
        try:
            flags |= extract_flags(wp.read_text(errors="ignore"))
        except Exception:
            pass
    # 只保留看起来像 flag 的(含常见前缀或就一个候选)
    pref = tuple(p.lower() for p in ("NSSCTF", "flag", "SUCTF", "GWCTF", "CISCN", "HGAME", "moectf",
                                     "GXY", "WUST", "LitCTF", "GHCTF", "SWPU", "HDCTF", "SEE", "KP"))
    strong = {f for f in flags if f.lower().startswith(pref)}
    return strong or flags


def _is_exe(f: Path) -> bool:
    try:
        h = f.read_bytes()[:4]
        return h[:2] == b"MZ" or h[:4] == b"\x7fELF"
    except Exception:
        return False


def pick_binary(problem_dir: Path):
    annex = problem_dir / "annex"
    files = [f for f in annex.rglob("*") if f.is_file()]
    if not files:
        return None
    exes = [f for f in files if _is_exe(f)]     # 优先真正的 PE/ELF 可执行(修A_game选错文件)
    if exes:
        return max(exes, key=lambda f: f.stat().st_size)
    files = [f for f in files if f.suffix.lower() not in (".md", ".txt", ".png", ".jpg")] or files
    return max(files, key=lambda f: f.stat().st_size)


def _is_multi_attachment(problem_dir: Path) -> bool:
    """压缩包解压出【多个】原始附件的题(如 basketball: Basketball.exe + array.txt 等 2+ 个原始文件):
    多是 Unity/大项目/多文件, 难又大(IDA分析易爆内存 + 超 35B 天花板), 跳过省时间(用户指定)。
    判据: extracted/(有则用, 否则 annex) 里原始文件 >1——排除 IDA 产物(.id0/.id1/.id2/.til/.nam)、压缩包、.DS_Store。
    单二进制(压缩包里就 1 个 exe, 如 4232/3692/6526)不算、正常跑。"""
    annex = problem_dir / "annex"
    if not annex.exists():
        return False
    # 排除非"附件": IDA产物 / 压缩包 / 说明文档(.md) / 调试符号(.pdb) / 脱壳产物(.unpacked)。
    # 保留数据文件(.txt/.enc 等——它们是题目附件, 如 basketball 的 array.txt)。同名去重(annex+extracted 各一份)。
    _skip_suf = (".id0", ".id1", ".id2", ".til", ".nam", ".zip", ".rar", ".7z", ".tar", ".gz",
                 ".md", ".pdb", ".unpacked")
    _skip_name = ("readme", ".ds_store")
    base = (annex / "extracted") if (annex / "extracted").exists() else annex
    names = {f.name for f in base.rglob("*")
             if f.is_file() and f.suffix.lower() not in _skip_suf
             and not any(s in f.name.lower() for s in _skip_name)
             and not any(seg.endswith(("_pyextract", "_unpacked", "_dump", "_extracted")) for seg in f.parts)}
    return len(names) > 1


def norm(flag: str) -> str:
    return flag.strip().strip("`").replace(" ", "")


def score(my_flag, truth: set) -> bool:
    # 前缀无关比对:NSSCTF 收录改写(HDCTF/LitCTF/HZCTF→NSSCTF)只换前缀,比花括号内容(救误杀)
    if not my_flag:
        return False
    from antirev.flag_check import _inner, _norm
    mi, mf = _inner(my_flag), _norm(my_flag)
    for t in truth:
        ti, tf = _inner(t), _norm(t)
        if mi and ti and (mi == ti or mi in tf or tf in mi or ti in mf or mf in ti):
            return True
    return False


def run_one(binary: Path, run_id: str, budget: int, stuck: int = 600) -> dict:
    t = time.time()
    # 20轮/10步, 全局预算=budget, stuck=无进展早停秒数; 子进程硬超时留 +60s 余量
    try:
        p = subprocess.run(
            [sys.executable, "-m", "antirev.solve_one", str(binary), run_id,
             "9999", "15", str(budget), str(stuck)],
            capture_output=True, text=True, timeout=budget + 60, cwd=str(ROOT))
        dt = time.time() - t
        for ln in reversed(p.stdout.splitlines()):
            if ln.startswith("__RESULT__"):
                return {**json.loads(ln[len("__RESULT__"):]), "wall_s": round(dt, 1)}
        return {"flag": None, "status": "no_result", "wall_s": round(dt, 1),
                "stderr_tail": p.stderr[-300:]}
    except subprocess.TimeoutExpired:
        return {"flag": None, "status": "timeout", "wall_s": budget}


_MLX_CMD = ["/Users/bytedance/miniconda3/envs/py3.13/bin/python3.13",
            "/Users/bytedance/miniconda3/envs/py3.13/bin/mlx_lm.server",
            "--model", "./Qwen3.6-35B-A3B-6bit", "--host", "0.0.0.0", "--port", "7777",
            "--temp", "0.2", "--top-p", "0.9", "--max-tokens", "65536",
            "--prompt-cache-size", "2", "--log-level", "INFO"]


def _mlx_ready() -> bool:
    import requests
    try:
        r = requests.post("http://127.0.0.1:7777/v1/chat/completions",
                          json={"model": "qwen3.6-35b-a3b-6bit",
                                "messages": [{"role": "user", "content": "hi"}],
                                "max_tokens": 2}, timeout=10)
        return r.status_code == 200
    except Exception:
        return False


def restart_mlx(wait: int = 300) -> bool:
    """每道题前重启 mlx, 防长跑累积内存被 swap 拖垮(见 memory mlx-swap-slowdown)。用户指定。"""
    subprocess.run(["pkill", "-f", "mlx_lm.server"], capture_output=True)
    time.sleep(3)
    with open("/tmp/mlx_eval.log", "a") as lg:
        subprocess.Popen(_MLX_CMD, cwd="/Users/bytedance", stdout=lg, stderr=lg,
                         start_new_session=True)
    t0 = time.time()
    while time.time() - t0 < wait:
        time.sleep(5)
        if _mlx_ready():
            print(f"  [mlx 重启完成, {time.time()-t0:.0f}s ready]", flush=True)
            return True
    print(f"  [mlx 重启超时 {wait}s!]", flush=True)
    return False


def steps_from_log(run_id: str) -> int:
    p = config.LOG_DIR / f"{run_id}.jsonl"
    if not p.exists():
        return 0
    n = 0
    for ln in p.read_text(errors="ignore").splitlines():
        try:
            if json.loads(ln).get("type") == "tool_result":
                n += 1
        except Exception:
            pass
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="train_set_1")
    ap.add_argument("--budget", type=int, default=3600)     # 单题上限1h
    ap.add_argument("--stuck", type=int, default=600)       # 10min无进展早停
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--only", default="")
    ap.add_argument("--concurrency", type=int, default=1)   # 并发跑题数(远程API可并发,大幅提效;本地mlx保持1)
    ap.add_argument("--remote", action="store_true")        # 远程API:跳过本地 mlx 重启(否则并发会冲突)
    args = ap.parse_args()

    probs_dir = ROOT / f"data/nssctf_reverse_l3_4/splits/{args.split}/problems"
    problems = sorted([d for d in probs_dir.iterdir() if d.is_dir()])
    only = set(args.only.split(",")) if args.only else None
    if only:
        problems = [p for p in problems if p.name.split("_")[0] in only]
    # §11 triage:按可解性排序,先打软柿子(可解题早出结果)
    def _score(pd):
        b = pick_binary(pd)
        return triage_score(b) if b else -1
    problems.sort(key=_score, reverse=True)
    if args.limit:
        problems = problems[:args.limit]

    out_path = config.LOG_DIR / f"eval_{args.split}_r{args.round}.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # 断点续跑:跳过本轮已完成的题
    done_pids, results, solved = set(), [], 0
    if out_path.exists():
        for ln in out_path.read_text(errors="ignore").splitlines():
            try:
                rec = json.loads(ln)
                done_pids.add(rec["pid"])
                results.append(rec)
                solved += rec.get("solved", False)
            except Exception:
                pass
    print(f"# 第{args.round}轮评估 {len(problems)} 题, budget={args.budget}s/题, "
          f"stuck={args.stuck}s (已完成{len(done_pids)}题跳过)\n")
    import threading
    from concurrent.futures import ThreadPoolExecutor
    _lock = threading.Lock()
    _prog = {"i": 0, "solved": solved}
    todo = [p for p in problems if p.name.split("_")[0] not in done_pids]

    def _process(pdir):
        pid = pdir.name.split("_")[0]
        binary = pick_binary(pdir)
        truth = ground_truth(pdir)
        run_id = f"eval_r{args.round}_{pid}"
        fmt = file_info(binary)["format"] if binary else None
        if not binary:
            rec = {"pid": pid, "title": pdir.name, "status": "no_binary",
                   "solved": False, "has_truth": bool(truth)}
        elif _is_multi_attachment(pdir):
            rec = {"pid": pid, "title": pdir.name, "binary": binary.name,
                   "status": "out_of_scope", "solved": False, "has_truth": bool(truth), "reason": "压缩包多附件"}
        elif fmt not in ("PE", "ELF"):
            rec = {"pid": pid, "title": pdir.name, "binary": binary.name, "format": fmt,
                   "status": "out_of_scope", "solved": False, "has_truth": bool(truth)}
        else:
            if not args.remote:
                restart_mlx()   # 本地 mlx 每题重启防 swap;远程 API 跳过(否则并发冲突)
            (config.LOG_DIR / f"{run_id}.jsonl").unlink(missing_ok=True)  # 清旧日志,免污染分析
            r = run_one(binary, run_id, args.budget, args.stuck)
            gt_ok = score(r.get("flag"), truth)
            produced = r.get("status") == "done" and bool(r.get("flag"))
            rec = {"pid": pid, "title": pdir.name, "binary": binary.name,
                   "my_flag": r.get("flag"), "truth": sorted(truth)[:3], "has_truth": bool(truth),
                   "status": r.get("status"), "solved": bool(produced or gt_ok),
                   "gt_verified": bool(gt_ok), "error": r.get("error"),
                   "steps": steps_from_log(run_id), "wall_s": r.get("wall_s")}
        with _lock:   # 结果写盘 + 计数 + 打印都加锁(并发安全)
            _prog["i"] += 1
            _prog["solved"] += rec["solved"]
            results.append(rec)
            with out_path.open("a") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            mark = "✅" if rec["solved"] else "❌"
            print(f"[{_prog['i']}/{len(todo)}] {mark} {pid} {pdir.name[:40]} | "
                  f"my={rec.get('my_flag')} status={rec['status']} steps={rec.get('steps')} {rec.get('wall_s')}s",
                  flush=True)
        return rec

    if args.concurrency > 1:
        print(f"# 并发 {args.concurrency} 题同时跑\n", flush=True)
        with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            list(pool.map(_process, todo))
    else:
        for pdir in todo:
            _process(pdir)
    solved = _prog["solved"]

    from collections import Counter
    in_scope = [r for r in results if r.get("status") != "out_of_scope"]  # 框架可跑的题(PE/ELF)
    denom = len(in_scope)
    gt_recs = [r for r in results if r.get("gt_verified")]
    with_truth = [r for r in in_scope if r.get("has_truth")]
    print(f"\n=== 汇总 ===")
    # 主口径:done-as-solved(产出通过反幻觉闸的 flag 即算解出),分母=in-scope
    print(f"★ 召回率(done-as-solved): {solved}/{denom} = {solved/max(1,denom)*100:.1f}%  "
          f"(超范围 {len(results)-denom} 题不计入分母)")
    # 真相基线:严格对照 wp 标准答案
    print(f"  其中 ground-truth 验证解出: {len(gt_recs)}/{len(with_truth)} "
          f"(有标准答案的 in-scope 题)= {[r['pid'] for r in gt_recs]}")
    solved_recs = [r for r in results if r["solved"]]
    unverified = [r["pid"] for r in solved_recs if not r.get("gt_verified")]
    if unverified:
        print(f"  产出但无标准答案可验证: {unverified}")
    if solved_recs:
        print(f"解出题平均步数: {sum(r['steps'] for r in solved_recs)/len(solved_recs):.1f}")
        print(f"解出题平均墙钟: {sum(r.get('wall_s',0) for r in solved_recs)/len(solved_recs):.1f}s")
        print(f"解出的题: {[r['pid'] for r in solved_recs]}")
    print(f"状态分布: {dict(Counter(r['status'] for r in results))}")


if __name__ == "__main__":
    main()
