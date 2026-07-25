"""outline 段图渲染:把 outline(分段地图)渲染成 AI/planner 可读的导航文本。

复用 render_fingerprint 渲染每段 feat;标注 ★核心段、[已看]/[未看]、未下钻计数。
"""
from antirev.memory.context import render_outline


def _outline():
    return {"addr": "0x401000", "n_blocks": 6, "n_insn": 60, "segments": [
        {"id": 0, "start": "0x401000", "end": "0x40102a", "n_insn": 10, "kind": "linear",
         "feat": {"loops": 0, "ops": [], "cmps": 0, "cmp_imms": [], "calls": ["read"],
                  "strs": [], "input": True, "size": 10}, "score": 4, "core": False},
        {"id": 1, "start": "0x40102a", "end": "0x401060", "n_insn": 14, "kind": "loop",
         "feat": {"loops": 1, "ops": [["xor", 0x37]], "cmps": 1, "cmp_imms": [], "calls": [],
                  "strs": ["Correct"], "input": False, "size": 20}, "score": 12, "core": True},
    ]}


def test_render_marks_core_and_coverage():
    r = render_outline(_outline(), seen={0})
    assert "★" in r                          # 核心段标星
    assert "xor 0x37" in r                    # 段级指纹被渲染(复用 render_fingerprint)
    assert "还有1" in r                        # 未下钻计数 = 2-1
    assert "[已看]" in r and "[未看]" in r     # seg0 已看 / seg1 未看


def test_render_without_seen_is_map_only():
    r = render_outline(_outline())            # planner 侧:无覆盖信息
    assert "★" in r and "xor 0x37" in r
    assert "已看" not in r                     # 不显示覆盖


def test_render_empty_is_safe():
    assert render_outline(None) == ""
    assert render_outline({"segments": []}) == ""
