"""单题求解子进程入口(供 eval harness 按题隔离 + 硬超时调用,§11)。

输出末尾一行 `__RESULT__{json}`,harness 从满是 IDA/angr 噪声的 stdout 里据此提取结果。
"""
import json
import sys

from antirev import config
from antirev.obs.logger import RunLogger
from antirev.graph.build import solve


def main():
    binary = sys.argv[1]
    run_id = sys.argv[2] if len(sys.argv) > 2 else "eval"
    max_replan = int(sys.argv[3]) if len(sys.argv) > 3 else 19    # 20 轮 planner↔executor
    max_steps = int(sys.argv[4]) if len(sys.argv) > 4 else 30     # 每轮 executor 最多 30 tool call
    budget = int(sys.argv[5]) if len(sys.argv) > 5 else None      # 单题总时长上限(秒)
    stuck_seconds = int(sys.argv[6]) if len(sys.argv) > 6 else 600  # 无新进展 10min → 提前判失败
    logger = RunLogger(run_id=run_id, log_dir=config.LOG_DIR)
    try:
        r = solve(binary, logger=logger, max_replan=max_replan, max_steps=max_steps,
                  budget=budget, stuck_seconds=stuck_seconds)
    except Exception as e:
        r = {"flag": None, "status": "error", "error": repr(e)[:300]}
    sys.stdout.write("\n__RESULT__" + json.dumps(r, ensure_ascii=False) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
