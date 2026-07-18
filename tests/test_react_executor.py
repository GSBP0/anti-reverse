"""自研 ReAct Executor:解析器单测(离线) + 模型驱动端到端(需端点)。"""
import urllib.request
from pathlib import Path

import pytest

from antirev import config
from antirev.react_executor import ReactExecutor, parse_step

ROOT = Path(__file__).resolve().parent.parent
PLAN = str(ROOT / "tests/fixtures/plan_flagcheck.md")


def _endpoint_up():
    try:
        urllib.request.urlopen(config.MODEL_BASE_URL.rstrip("/") + "/models", timeout=2)
        return True
    except Exception:
        return False


def test_parse_action():
    kind, p = parse_step('THOUGHT: 先定位\nACTION: {"tool":"solve_locate","args":{}}')
    assert kind == "action" and p["tool"] == "solve_locate" and p["args"] == {}


def test_parse_action_with_trailing_text():
    kind, p = parse_step('ACTION: {"tool":"solve_angr","args":{"stdin_len":17}} 然后等待')
    assert kind == "action" and p["args"]["stdin_len"] == 17


def test_parse_function_format():
    kind, p = parse_step('<function=solve_verify>{"candidate":"flag{x}"}</function>')
    assert kind == "action" and p["tool"] == "solve_verify"


def test_parse_final():
    kind, p = parse_step("THOUGHT: done\nFINAL: flag{abc}")
    assert kind == "final" and p == "flag{abc}"


def test_parse_garbage_returns_none():
    kind, p = parse_step("我不知道该怎么做")
    assert kind is None


@pytest.mark.skipif(not _endpoint_up(), reason="model endpoint offline")
def test_model_driven_end_to_end(sample, expected_flag):
    ex = ReactExecutor(sample)
    result = ex.run(open(PLAN).read())
    assert result["flag"] and expected_flag in result["flag"], result
