"""内容感知折叠 + 分页取回(应对反编译/反汇编大返回)。

- _fold_repeats: 折叠"连续同类行"(治密度,花指令的重复 pass 压掉),不同行全留 → 无损于信息、有损于冗余。
- paginate:    对(折叠后的)文本按页无损切分,带 total_pages/has_next,供 recall 逐页取全。
"""
import json

from antirev.memory.context import _fold_repeats, paginate, recall_view


# ———— _fold_repeats:折叠冗余、保留信息 ————
def test_fold_no_repeats_returns_unchanged():
    src = "a = 1;\nb = 2;\nc = 3;"
    assert _fold_repeats(src) == src


def test_fold_collapses_identical_run():
    src = "start();\n" + "acc += 1;\n" * 5 + "return acc;"
    out = _fold_repeats(src)
    assert out.count("\n") < src.count("\n")   # 行数变少
    assert "acc += 1;" in out                  # 保留一份代表样本
    assert "折叠" in out and "5" in out         # 标注折叠了多少


def test_fold_disasm_ignores_address_prefix():
    # 反汇编每行带不同地址,但指令体相同(花指令 nop 雪橇)→ 归一化地址后应折叠
    src = "\n".join(f"0x40100{i}  nop" for i in range(6))
    out = _fold_repeats(src)
    assert out.count("\n") < src.count("\n")
    assert "折叠" in out


def test_fold_short_run_below_threshold_kept():
    # 只连续 2 行相同(< min_run=3)→ 不折叠,原样
    src = "x();\ndup;\ndup;\ny();"
    assert _fold_repeats(src) == src


def test_fold_preserves_distinct_lines_around_run():
    src = "HEAD_UNIQUE;\n" + "pass;\n" * 4 + "TAIL_UNIQUE;"
    out = _fold_repeats(src)
    assert "HEAD_UNIQUE;" in out and "TAIL_UNIQUE;" in out


# ———— paginate:无损分页 ————
def test_paginate_single_page_when_fits():
    r = paginate("l1\nl2\nl3", page=1, num=10)
    assert r["total_lines"] == 3
    assert r["total_pages"] == 1
    assert r["has_next"] is False
    assert r["text"] == "l1\nl2\nl3"


def test_paginate_across_pages():
    text = "\n".join(f"line{i}" for i in range(1, 6))  # 5 行
    p1 = paginate(text, page=1, num=2)
    assert p1["total_pages"] == 3
    assert p1["text"] == "line1\nline2"
    assert p1["has_next"] is True
    p3 = paginate(text, page=3, num=2)
    assert p3["text"] == "line5"
    assert p3["has_next"] is False


def test_paginate_page_out_of_range_is_empty_not_error():
    text = "\n".join(f"line{i}" for i in range(1, 6))
    r = paginate(text, page=9, num=2)
    assert r["text"] == ""
    assert r["has_next"] is False
    assert r["total_pages"] == 3


def test_paginate_empty_text():
    r = paginate("", page=1, num=10)
    assert r["total_lines"] == 0
    assert r["text"] == ""
    assert r["has_next"] is False


# ———— recall_view:从 artifact 全文提取代码 → 折叠 → 分页 ————
def test_recall_view_extracts_pseudocode_and_paginates():
    ft = json.dumps({"pseudocode": "\n".join(f"L{i}" for i in range(1, 6))})  # 5 行无重复
    r = recall_view(ft, page=1, num=2)
    assert r["total_pages"] == 3
    assert r["text"] == "L1\nL2"
    assert r["has_next"] is True


def test_recall_view_folds_repeats_in_code():
    ft = json.dumps({"pseudocode": "head\n" + "dup;\n" * 10 + "tail"})
    r = recall_view(ft, page=1, num=100)
    assert "折叠" in r["text"]                 # 冗余被折叠,不逐行回灌


def test_recall_view_reads_disasm_when_no_pseudocode():
    ft = json.dumps({"disasm": "\n".join(f"0x40100{i}  insn{i}" for i in range(3))})
    r = recall_view(ft, page=1, num=100)
    assert "insn0" in r["text"] and "insn2" in r["text"]


def test_recall_view_falls_back_to_full_text():
    # 非反编译 artifact(无 pseudocode/disasm)→ 回退对全文分页,仍可无损取回、不报错
    ft = json.dumps({"stdout": "hello", "returncode": 0})
    r = recall_view(ft, page=1, num=100)
    assert "hello" in r["text"]
