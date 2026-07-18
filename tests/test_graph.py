from antirev.graph.nodes import make_router, _pre_analyze
from antirev.graph.build import build_graph
from antirev.react_executor import ChatClient


def test_router_logic():
    route = make_router(max_replan=2)
    assert route({"flag": "NSSCTF{x}"}) == "done"
    assert route({"replan_count": 1}) == "replan"     # 未超上限 → 重规划
    assert route({"replan_count": 3}) == "fail"        # 超上限 → 失败


def test_pre_analyze_extracts_hints(sample):
    pre = _pre_analyze(sample)
    assert pre["file_info"]["format"] == "ELF"
    assert pre["file_info"]["arch"] == "x86-64"
    assert any("Correct" in s or "Wrong" in s for s in pre["hint_strings"])


def test_graph_compiles():
    assert build_graph(ChatClient()) is not None
