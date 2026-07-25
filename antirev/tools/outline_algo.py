"""纯切段算法(stdlib-only,worker 与 pytest 双导入):把 basic block 列表切成语义段并打分。

worker `_outline` 用 ida_gdl.FlowChart 把函数归一化成纯 tuple blocks 后喂这里 —— 故脱 IDA 可单测。
block 契约: {start:int, end:int, succs:[int], calls_after:[int], n_insn:int}
段契约:    {start:int, end:int, kind:"loop"|"linear", n_insn:int}
"""

# 关键串词表(与 ida_worker._KEY_STR 一致;此处独立以保持 stdlib-only 双导入)
KEY_STR = ("flag", "wrong", "correct", "right", "incorrect", "success", "fail",
           "congrat", "well done", "nice", "good job", "try again", "invalid",
           "password", "please input", "enter", "key")


def _union_overlapping(spans):
    if not spans:
        return []
    spans = sorted(set(spans))
    merged = [spans[0]]
    for s, e in spans[1:]:
        ls, le = merged[-1]
        if s <= le:                       # 重叠/相邻 → 合并(嵌套/同头循环归一)
            merged[-1] = (ls, max(le, e))
        else:
            merged.append((s, e))
    return merged


def detect_loop_spans(blocks):
    """后向边(后继指回自身起点或更早地址)= 循环。返回合并后的 [(header, latch_end)]。"""
    spans = []
    for b in blocks:
        for s in b["succs"]:
            if s <= b["start"]:               # 后向边 latch b → header s
                spans.append((s, b["end"]))    # 循环 span [header, latch_end)
    return _union_overlapping(spans)


def _coalesce_tiny(segs, min_seg_insn):
    """<min 指令的碎段(碎 linear / 花指令自跳的假 loop)并入相邻 linear;有体量的 loop(≥min)保留。
    合并后归为 linear(假 loop 的循环性被消解)。被真循环包夹、无 linear 邻居则保留。"""
    segs = [dict(s) for s in segs]
    changed = True
    while changed and len(segs) > 1:
        changed = False
        for i, seg in enumerate(segs):
            if seg["n_insn"] >= min_seg_insn:
                continue
            if i > 0 and segs[i - 1]["kind"] == "linear":
                segs[i - 1]["end"] = seg["end"]
                segs[i - 1]["n_insn"] += seg["n_insn"]
                segs.pop(i)
            elif i + 1 < len(segs) and segs[i + 1]["kind"] == "linear":
                nxt = segs[i + 1]
                nxt["start"] = seg["start"]
                nxt["n_insn"] += seg["n_insn"]
                segs.pop(i)
            else:
                continue                      # 无 linear 邻居(真循环包夹/孤立)→ 保留
            changed = True
            break
    return segs


def segment_blocks(blocks, fstart, fend, min_seg_insn=4):
    """按循环边界 + 循环外的 call 后地址切段;循环体独立成段;tiny linear 合并。"""
    spans = detect_loop_spans(blocks)

    def in_loop(a):
        return any(s <= a < e for (s, e) in spans)

    cuts = {fstart, fend}
    for (s, e) in spans:                      # 循环边界一律是切点(保循环体独立)
        cuts.add(s)
        cuts.add(e)
    for b in blocks:
        for c in b["calls_after"]:            # 循环外的 call 后是切点;循环内不切
            if not in_loop(c):
                cuts.add(c)
    cuts = sorted(c for c in cuts if fstart <= c <= fend)
    segs = []
    for lo, hi in zip(cuts, cuts[1:]):
        kind = "loop" if any(s <= lo and hi <= e for (s, e) in spans) else "linear"
        n = sum(b["n_insn"] for b in blocks if lo <= b["start"] < hi)
        segs.append({"start": lo, "end": hi, "kind": kind, "n_insn": n})
    return _coalesce_tiny(segs, min_seg_insn)


def score_segment(feat, kind):
    """段级'像不像核心算法'评分:循环 + 数据变换 ops + 比较 + 关键串 + 读输入 + 调用。"""
    s = 0
    if kind == "loop":
        s += 3
    s += min(len(feat.get("ops") or []), 4) * 2
    if feat.get("cmp_imms") or feat.get("cmps"):
        s += 2
    if any(k in x.lower() for x in (feat.get("strs") or []) for k in KEY_STR):
        s += 5
    if feat.get("input"):
        s += 3
    s += min(len(feat.get("calls") or []), 3)
    return s
