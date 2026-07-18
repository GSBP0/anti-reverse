"""MVP 入口:对一个二进制启动 ReAct Executor 流程(自研文本协议,适配 mlx_lm.server)。

用法:
    conda run -n antirev python main.py <binary> [plan.md]
需模型端点 config.MODEL_BASE_URL(mlx_lm.server)在线。
"""
import sys

from antirev import config
from antirev.obs.logger import RunLogger
from antirev.react_executor import ReactExecutor


def main():
    if len(sys.argv) < 2:
        print("usage: python main.py <binary> [plan.md]")
        sys.exit(1)
    binary = sys.argv[1]
    plan = open(sys.argv[2]).read() if len(sys.argv) > 2 else "解出该二进制的 flag。"
    run_id = sys.argv[3] if len(sys.argv) > 3 else "cli"
    logger = RunLogger(run_id=run_id, log_dir=config.LOG_DIR)
    ex = ReactExecutor(binary, logger=logger)
    result = ex.run(plan)
    print("\n=== RESULT ===")
    print(f"flag: {result.get('flag')}")
    print(f"steps: {result.get('steps')}  error: {result.get('error')}")


if __name__ == "__main__":
    main()
