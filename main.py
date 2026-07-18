"""入口:对一个二进制启动双 Agent(Planner + Executor)流程(§3)。

用法:
    conda run -n antirev python main.py <binary> [run_id]
需模型端点 config.MODEL_BASE_URL(mlx_lm.server)在线。
"""
import sys

from antirev import config
from antirev.obs.logger import RunLogger
from antirev.graph.build import solve


def main():
    if len(sys.argv) < 2:
        print("usage: python main.py <binary> [run_id]")
        sys.exit(1)
    binary = sys.argv[1]
    run_id = sys.argv[2] if len(sys.argv) > 2 else "cli"
    logger = RunLogger(run_id=run_id, log_dir=config.LOG_DIR)
    result = solve(binary, logger=logger)
    print("\n=== RESULT ===")
    print(f"flag: {result.get('flag')} | status: {result.get('status')} | replans: {result.get('replans')}")


if __name__ == "__main__":
    main()
