"""单题求解子进程入口(供 eval harness 与 Web 作战台按题隔离 + 硬超时调用,§11)。

输出末尾一行 `__RESULT__{json}`,调用方从满是 IDA/angr 噪声的 stdout 里据此提取结果。
"""
import json
import sys

from antirev import config, ctl
from antirev.obs.logger import RunLogger
from antirev.graph.build import solve


def main():
    binary = sys.argv[1]
    run_id = sys.argv[2] if len(sys.argv) > 2 else "eval"
    max_replan = int(sys.argv[3]) if len(sys.argv) > 3 else 9999  # 不限轮数, 仅靠 budget/stuck 时间限制
    max_steps = int(sys.argv[4]) if len(sys.argv) > 4 else 15     # 每轮 executor 最多 15 tool call
    budget = int(sys.argv[5]) if len(sys.argv) > 5 else None      # 单题总时长上限(秒)
    stuck_seconds = int(sys.argv[6]) if len(sys.argv) > 6 else 600  # 无新进展 10min → 提前判失败
    ctl.install_signal_handler(run_id)   # SIGTERM → StopRequested(即时打断阻塞调用)
    logger = RunLogger(run_id=run_id, log_dir=config.LOG_DIR)
    try:
        r = solve(binary, logger=logger, max_replan=max_replan, max_steps=max_steps,
                  budget=budget, stuck_seconds=stuck_seconds)
    except ctl.StopRequested as e:
        # StopRequested 继承 BaseException,下面那个 except Exception 抓不到它 —— 必须单列,
        # 否则人工停止时 __RESULT__ 那行不会输出,调用方拿不到结果。
        r = {"flag": None, "status": "stopped", "error": str(e)[:300]}
    except Exception as e:
        r = {"flag": None, "status": "error", "error": repr(e)[:300]}
    sys.stdout.write("\n__RESULT__" + json.dumps(r, ensure_ascii=False) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
