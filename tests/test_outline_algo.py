"""纯切段算法(脱 IDA):把 basic block 列表按循环回边/调用边界切成语义段,并给段打分选核心。

worker `_outline` 用 ida_gdl.FlowChart 把函数归一化成纯 tuple blocks,再喂这里的纯函数 —— 故可脱 IDA 单测。
block 契约: {start:int, end:int, succs:[int], calls_after:[int], n_insn:int}
段契约:    {start:int, end:int, kind:"loop"|"linear", n_insn:int}
"""
from antirev.tools.outline_algo import segment_blocks, detect_loop_spans, score_segment


def _bb(start, end, succs, n_insn=4, calls_after=None):
    return {"start": start, "end": end, "succs": succs,
            "calls_after": calls_after or [], "n_insn": n_insn}


def test_detect_loop_span_from_back_edge():
    # BB1 有指回自身起点的后向边 → 循环 span=[header, latch_end)
    blocks = [_bb(0x0, 0x10, [0x10]), _bb(0x10, 0x20, [0x10, 0x20]), _bb(0x20, 0x30, [])]
    spans = detect_loop_spans(blocks)
    assert (0x10, 0x20) in spans


def test_segment_isolates_loop_body():
    # prologue | loop 体 | epilogue → 循环体恰好单独成一个 loop 段
    blocks = [_bb(0x0, 0x10, [0x10]), _bb(0x10, 0x20, [0x10, 0x20]), _bb(0x20, 0x30, [])]
    segs = segment_blocks(blocks, 0x0, 0x30)
    loops = [s for s in segs if s["kind"] == "loop"]
    assert len(loops) == 1
    assert (loops[0]["start"], loops[0]["end"]) == (0x10, 0x20)
    assert len(segs) == 3


def test_no_loop_collapses_to_single_segment():
    # 纯线性、无循环无调用 → 不该碎成多段,一段即可
    blocks = [_bb(0x0, 0x10, [0x10]), _bb(0x10, 0x20, [])]
    segs = segment_blocks(blocks, 0x0, 0x20)
    assert len(segs) == 1
    assert segs[0]["kind"] == "linear"


def test_call_outside_loop_splits_segment():
    # 循环外的 call 之后是切点
    blocks = [_bb(0x0, 0x10, [0x10], calls_after=[0x10]), _bb(0x10, 0x20, [])]
    segs = segment_blocks(blocks, 0x0, 0x20)
    assert len(segs) == 2


def test_call_inside_loop_does_not_split_body():
    # 循环体内的 call 不切,保循环体完整成段
    blocks = [_bb(0x0, 0x10, [0x10]),
              _bb(0x10, 0x20, [0x10, 0x20], calls_after=[0x18]),
              _bb(0x20, 0x30, [])]
    segs = segment_blocks(blocks, 0x0, 0x30)
    loops = [s for s in segs if s["kind"] == "loop"]
    assert len(loops) == 1 and (loops[0]["start"], loops[0]["end"]) == (0x10, 0x20)


def test_tiny_linear_coalesces():
    # 循环外 call 切出一个 2 指令 linear 碎片 → 并入后继 linear,不留 dust(无合并则会是 2 段)
    blocks = [_bb(0x0, 0x8, [0x8], n_insn=2, calls_after=[0x8]),
              _bb(0x8, 0x20, [], n_insn=6)]
    segs = segment_blocks(blocks, 0x0, 0x20, min_seg_insn=4)
    assert len(segs) == 1


def test_tiny_loop_coalesced_as_junk():
    # 花指令 1 指令自跳形成的"循环"应被当 dust 并入相邻,不留误导性 tiny loop 段(funnyre main 实测)
    blocks = [_bb(0x0, 0x8, [0x8], n_insn=4),
              _bb(0x8, 0xa, [0x8], n_insn=1),      # 1-insn 自跳 = 花指令假循环
              _bb(0xa, 0x20, [], n_insn=6)]
    segs = segment_blocks(blocks, 0x0, 0x20, min_seg_insn=4)
    assert all(not (s["kind"] == "loop" and s["n_insn"] < 4) for s in segs)


def test_score_picks_loop_transform_as_core():
    # 循环内 xor 变换 + 引用对错串 的段,应比纯读输入的 linear prologue 得分高
    loop_feat = {"loops": 1, "ops": [["xor", 0x37]], "cmps": 1, "cmp_imms": [],
                 "calls": [], "strs": ["Correct"], "input": False, "size": 20}
    lin_feat = {"loops": 0, "ops": [], "cmps": 0, "cmp_imms": [],
                "calls": ["read"], "strs": [], "input": True, "size": 10}
    assert score_segment(loop_feat, "loop") > score_segment(lin_feat, "linear")
