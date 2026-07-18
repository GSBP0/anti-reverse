"""MVP 入口:对一个二进制启动 ReAct Executor 流程。

用法:
    conda run -n antirev python main.py <binary> [plan.md]
需模型端点 config.MODEL_BASE_URL 在线。
"""
import sys

from antirev.executor_mvp import build_executor


def main():
    if len(sys.argv) < 2:
        print("usage: python main.py <binary> [plan.md]")
        sys.exit(1)
    binary = sys.argv[1]
    plan = open(sys.argv[2]).read() if len(sys.argv) > 2 else "解出该二进制的 flag。"
    agent = build_executor(binary)
    out = agent.invoke({"messages": [("user", plan)]})
    print(out["messages"][-1].content)


if __name__ == "__main__":
    main()
