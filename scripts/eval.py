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


def norm(flag: str) -> str:
    return flag.strip().strip("`").replace(" ", "")


def score(my_flag, truth: set) -> bool:
    if not my_flag:
        return False
    m = norm(my_flag)
    return any(m == norm(t) or norm(t) in m or m in norm(t) for t in truth)


def run_one(binary: Path, run_id: str, budget: int, stuck: int = 600) -> dict:
    t = time.time()
    # 20轮/30步, 全局预算=budget, stuck=无进展早停秒数; 子进程硬超时留 +60s 余量
    try:
        p = subprocess.run(
            [sys.executable, "-m", "antirev.solve_one", str(binary), run_id,
             "19", "30", str(budget), str(stuck)],
            capture_output=True, text=True, timeout=budget + 60, cwd=str(ROOT))
        dt = time.time() - t
        for ln in reversed(p.stdout.splitlines()):
            if ln.startswith("__RESULT__"):
                return {**json.loads(ln[len("__RESULT__"):]), "wall_s": round(dt, 1)}
        return {"flag": None, "status": "no_result", "wall_s": round(dt, 1),
                "stderr_tail": p.stderr[-300:]}
    except subprocess.TimeoutExpired:
        return {"flag": None, "status": "timeout", "wall_s": budget}


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
    for i, pdir in enumerate(problems, 1):
        pid = pdir.name.split("_")[0]
        if pid in done_pids:
            continue
        binary = pick_binary(pdir)
        truth = ground_truth(pdir)
        run_id = f"eval_r{args.round}_{pid}"
        fmt = file_info(binary)["format"] if binary else None
        if not binary:
            rec = {"pid": pid, "title": pdir.name, "status": "no_binary",
                   "solved": False, "has_truth": bool(truth)}
        elif fmt not in ("PE", "ELF"):
            # §11 跨题triage:非 PE/ELF(pyc/txt/apk/Unity等)超本框架范围,快速跳过不浪费预算
            rec = {"pid": pid, "title": pdir.name, "binary": binary.name, "format": fmt,
                   "status": "out_of_scope", "solved": False, "has_truth": bool(truth)}
        else:
            (config.LOG_DIR / f"{run_id}.jsonl").unlink(missing_ok=True)  # 清旧日志,免污染分析
            r = run_one(binary, run_id, args.budget, args.stuck)
            ok = score(r.get("flag"), truth)
            rec = {"pid": pid, "title": pdir.name, "binary": binary.name,
                   "my_flag": r.get("flag"), "truth": sorted(truth)[:3], "has_truth": bool(truth),
                   "status": r.get("status"), "solved": ok,
                   "steps": steps_from_log(run_id), "wall_s": r.get("wall_s")}
        solved += rec["solved"]
        results.append(rec)
        with out_path.open("a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        mark = "✅" if rec["solved"] else "❌"
        print(f"[{i}/{len(problems)}] {mark} {pid} {pdir.name[:40]} | "
              f"my={rec.get('my_flag')} status={rec['status']} steps={rec.get('steps')} {rec.get('wall_s')}s")

    from collections import Counter
    with_truth = [r for r in results if r.get("has_truth")]
    print(f"\n=== 汇总 ===")
    print(f"总解出率(有标准答案的题): {solved}/{len(with_truth)} = "
          f"{solved/max(1,len(with_truth))*100:.1f}%  (另有 {len(results)-len(with_truth)} 题无标准答案未计)")
    solved_recs = [r for r in results if r["solved"]]
    if solved_recs:
        print(f"解出题平均步数: {sum(r['steps'] for r in solved_recs)/len(solved_recs):.1f}")
        print(f"解出题平均墙钟: {sum(r.get('wall_s',0) for r in solved_recs)/len(solved_recs):.1f}s")
        print(f"解出的题: {[r['pid'] for r in solved_recs]}")
    print(f"状态分布: {dict(Counter(r['status'] for r in results))}")


if __name__ == "__main__":
    main()
