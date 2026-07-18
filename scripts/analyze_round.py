"""分析某轮召回的所有解题过程,汇总缺陷模式(供"分析→改进"步骤)。

用法: conda run -n antirev python scripts/analyze_round.py --round 1
读 logs/eval_train_set_1_r{N}.jsonl(结果) + logs/eval_r{N}_{pid}.jsonl(每题轨迹),
输出: 解出率 / 失败原因分布 / 每题工具用量+轮数+卡点 / 常见缺陷聚类。
"""
from __future__ import annotations
import argparse
import json
from collections import Counter
from pathlib import Path

from antirev import config

LOG = config.LOG_DIR


def load_traj(run_id):
    p = LOG / f"{run_id}.jsonl"
    if not p.exists():
        return []
    out = []
    for ln in p.read_text(errors="ignore").splitlines():
        try:
            out.append(json.loads(ln))
        except Exception:
            pass
    return out


def analyze_challenge(pid, rnd):
    traj = load_traj(f"eval_r{rnd}_{pid}")
    tools = [r for r in traj if r["type"] == "tool_result"]
    plans = [r for r in traj if r["type"] == "plan_md"]
    outs = [r for r in traj if r["type"] == "executor_output"]
    stuck = [r for r in traj if r["type"] == "stuck_no_progress"]
    rejected = [r for r in traj if r["type"] == "final_rejected"]
    tdist = Counter(r["tool"] for r in tools)
    solve_attempts = sum(tdist[t] for t in
                         ("run_python", "solve_locate", "solve_angr", "solve_verify"))
    # 最后一次模型思考(常暴露卡点)
    last_thought = outs[-1]["text"][:160].replace("\n", " ") if outs else ""
    return {"rounds": len(plans), "tools": len(tools), "tdist": dict(tdist),
            "solve_attempts": solve_attempts, "stuck": len(stuck),
            "rejected_final": len(rejected), "last_thought": last_thought}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--split", default="train_set_1")
    args = ap.parse_args()

    res_path = LOG / f"eval_{args.split}_r{args.round}.jsonl"
    if not res_path.exists():
        print(f"无结果文件 {res_path}")
        return
    results = [json.loads(l) for l in res_path.read_text().splitlines() if l.strip()]

    with_truth = [r for r in results if r.get("has_truth")]
    solved = [r for r in results if r["solved"]]
    print(f"=== 第{args.round}轮 分析({len(results)}题) ===")
    print(f"解出率(有答案题): {len(solved)}/{len(with_truth)} = "
          f"{len(solved)/max(1,len(with_truth))*100:.1f}%")
    print(f"状态分布: {dict(Counter(r['status'] for r in results))}")
    print(f"解出: {[r['pid'] for r in solved]}\n")

    print("=== 逐题(非解出的看卡点) ===")
    for r in results:
        if r["status"] in ("out_of_scope", "no_binary"):
            continue
        a = analyze_challenge(r["pid"], args.round)
        mark = "✅" if r["solved"] else "❌"
        flags = []
        if a["rejected_final"]:
            flags.append(f"拒假阳性x{a['rejected_final']}")
        if a["stuck"]:
            flags.append("stuck早停")
        if a["solve_attempts"] == 0 and a["tools"] > 3:
            flags.append("纯探索没尝试解")
        if a["solve_attempts"] >= 8:
            flags.append("反复尝试解未果")
        print(f"{mark} {r['pid']} {r['title'][:30]} | {r['status']} {r.get('wall_s')}s "
              f"| 轮{a['rounds']} 工具{a['tools']} 解题尝试{a['solve_attempts']} "
              f"| {' '.join(flags)}")
        if not r["solved"] and a["last_thought"]:
            print(f"     末思考: {a['last_thought']}")

    # 缺陷聚类
    print("\n=== 缺陷聚类(非解出题) ===")
    patterns = Counter()
    for r in results:
        if r["solved"] or r["status"] in ("out_of_scope", "no_binary"):
            continue
        a = analyze_challenge(r["pid"], args.round)
        if a["rejected_final"] >= 2:
            patterns["反复产出假阳性(算错还输出)"] += 1
        if a["stuck"]:
            patterns["10min无解题进展早停(纯探索/迷路)"] += 1
        if a["solve_attempts"] >= 8:
            patterns["反复解题尝试失败(算法魔改/参数错)"] += 1
        if r["status"] == "timeout":
            patterns["超1h硬超时"] += 1
        if a["tools"] > 40 and a["solve_attempts"] < 3:
            patterns["大二进制导航吃步数"] += 1
    for pat, n in patterns.most_common():
        print(f"  {n}题: {pat}")


if __name__ == "__main__":
    main()
