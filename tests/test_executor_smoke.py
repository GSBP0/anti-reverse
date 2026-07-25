"""模型驱动端到端冒烟(§14 step 1 有模型部分)。需 127.0.0.1:7777 在线,否则跳过。"""
import urllib.request
from pathlib import Path

import pytest

from antirev import config
from antirev.executor_mvp import build_executor, build_tools

ROOT = Path(__file__).resolve().parent.parent
PLAN = str(ROOT / "tests/fixtures/plan_flagcheck.md")


def _endpoint_up():
    try:
        urllib.request.urlopen(config.MODEL_BASE_URL.rstrip("/") + "/models", timeout=2)
        return True
    except Exception:
        return False


def test_executor_constructs_without_endpoint(sample):
    """不依赖端点:能装配 agent + 5 个工具(捕获 API 层错误)。"""
    tools = build_tools(sample)
    assert len(tools) == 5
    names = {t.name for t in tools}
    assert {"ida_decompile", "solve_locate", "solve_angr", "solve_verify", "terminal"} == names
    assert build_executor(sample) is not None


@pytest.mark.skipif(not _endpoint_up(), reason="model endpoint offline")
def test_executor_solves_flagcheck(sample, expected_flag):
    agent = build_executor(sample)
    plan = open(PLAN).read()
    out = agent.invoke({"messages": [("user", f"按下面 Plan 解出 flag,只用提供的工具。\n\n{plan}")]},
                       {"recursion_limit": 30})
    text = str(out["messages"][-1].content)
    assert expected_flag in text
