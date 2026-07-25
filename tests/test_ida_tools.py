import os
from pathlib import Path

import pytest

from antirev.tools.ida_tools import IdaSession

_FUNNYRE = str(Path(__file__).resolve().parent.parent /
               "data/nssctf_reverse_l3_4/problems/2000_[WUSTCTF 2020]funnyre/annex/attachment")


def test_lists_entry_function(sample):
    with IdaSession(sample) as ida:
        fns = ida.list_functions()
        assert any(f["name"] == "start" for f in fns), fns


def test_decompile_returns_pseudocode(sample):
    with IdaSession(sample) as ida:
        r = ida.decompile("0x400078")
        assert "pseudocode" in r
        assert "sys_read" in r["pseudocode"] or "read" in r["pseudocode"].lower()


def test_xrefs_to_message_string(sample):
    # "Correct" 串应有来自 correct 分支 lea 的 xref(地址动态取,不硬编码)
    with IdaSession(sample) as ida:
        correct = [s for s in ida.strings() if "Correct" in s["value"]]
        assert correct, "IDA 应检测到 Correct 串"
        refs = ida.xrefs_to(correct[0]["addr"])
        assert refs, "Correct 串应有 xref"


def test_decompile_carries_algorithm_fingerprint(sample):
    """decompile 返回带 fingerprint_feat:主环境 render 出的指纹保留密钥常量(xor 0x37)与循环结构。
    这是'算法指纹'的真机验证——worker 从汇编抽 feat,主环境 render_fingerprint 渲染。"""
    from antirev.memory.context import render_fingerprint
    with IdaSession(sample) as ida:
        r = ida.decompile("0x400078")   # start:循环逐字节 xor 0x37 再比较
        feat = r.get("fingerprint_feat")
        assert feat is not None, r
        fp = render_fingerprint(feat)
        assert "loop" in fp, fp          # 循环逐字节
        assert "xor 0x37" in fp, fp      # 密钥常量被抽出(裸签名给不出)


def test_outline_segments_flagcheck(sample):
    """真机:大函数分段地图。flagcheck 太小,放宽门槛(min_insn=0)验证算法在真实 IDA 输出上工作。"""
    with IdaSession(sample) as ida:
        outline = ida.outline("0x400078", min_insn=0)
        assert outline is not None, "放宽门槛应产出 outline"
        segs = outline["segments"]
        assert len(segs) >= 2
        cores = [s for s in segs if s["core"]]
        assert len(cores) == 1 and cores[0]["kind"] == "loop"     # 核心=循环体
        assert ["xor", 0x37] in cores[0]["feat"]["ops"]           # 循环段抽出密钥


def test_disasm_range_returns_segment(sample):
    """真机:disasm 带 end 只反汇编 [ea,end),严格少于整函数(B+ 局部下钻)。"""
    with IdaSession(sample) as ida:
        whole = ida.disasm("0x400078")["disasm"]
        part = ida.disasm("0x400078", end="0x400099")["disasm"]
        assert part and part.count("\n") < whole.count("\n")


def test_decompile_gates_outline_off_for_small_func(sample):
    """真机:默认门槛下 flagcheck(~30指令/~6块)不生成 outline(分级:小函数指纹已够)。"""
    with IdaSession(sample) as ida:
        assert ida.decompile("0x400078").get("outline") is None


@pytest.mark.skipif(not os.path.exists(_FUNNYRE), reason="funnyre 真题样本不在仓库")
def test_outline_funnyre_real_regression():
    """真题 2000(funnyre 花指令)回归:锁住 driver 实测发现并修的 3 个 bug,防退化。"""
    from antirev.memory.context import render_fingerprint
    with IdaSession(_FUNNYRE) as ida:
        # ① 核心加密函数 0x4004c0(57指令)出多段 outline 且含 xor 变换(门槛 60→40 修复)
        o = ida.outline("0x4004c0")
        assert o and len(o["segments"]) >= 2
        assert any(m == "xor" for s in o["segments"] for m, _ in s["feat"]["ops"])
        # ② 花指令 main 线性无多段结构 → 不产生误导 outline(花指令假循环消解修复)
        assert ida.outline("0x4005b0") is None
        # ③ 花指令 main 指纹有界:几百个不同 xor 立即数不得渲染成几千字符(ops cap 修复)
        assert len(render_fingerprint(ida.decompile("0x4005b0")["fingerprint_feat"])) < 400
