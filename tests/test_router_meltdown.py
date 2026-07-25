"""router 空转熔断单测(回归防线)。

背景:早先阈值是"连续 4 轮无 verified/候选/flag 即 fail",把慢热题误杀——
R21 里 3790 用 90 步(~7 轮)、4232 也需多轮才解出,R23 里双双被熔断打成 stuck。
现规则:必须 **6 轮无产出 且 台账停止增长**(还在学到新东西就不算空转)。
"""
from antirev.graph.nodes import make_router


def _rounds(n, ledger_len=1000, growing=False):
    return [{"last_state": {"verified": set(), "candidate": None}, "flag": None,
             "ledger": "x" * (ledger_len + (i * 500 if growing else 0))}
            for i in range(n)]


def test_no_meltdown_while_ledger_grows():
    """慢热题:多轮没产出但台账一直在长(仍在获取新信息)→ 继续 replan,别熔断。"""
    r = make_router(max_replan=9999)
    assert r({"evidence": _rounds(6, growing=True)}) == "replan"


def test_meltdown_when_stagnant():
    """真空转:6 轮无产出且台账不长 → fail,省 budget。"""
    r = make_router(max_replan=9999)
    assert r({"evidence": _rounds(6)}) == "fail"


def test_no_meltdown_before_threshold():
    """不足 6 轮不熔断(旧的 4 轮阈值过严)。"""
    r = make_router(max_replan=9999)
    assert r({"evidence": _rounds(4)}) == "replan"
    assert r({"evidence": _rounds(5)}) == "replan"


def test_flag_wins():
    r = make_router(max_replan=9999)
    assert r({"flag": "NSSCTF{x}", "evidence": _rounds(6)}) == "done"


def test_meltdown_not_triggered_when_candidate_found():
    """有候选=有进展,不熔断。"""
    r = make_router(max_replan=9999)
    ev = _rounds(6)
    ev[-1]["last_state"]["candidate"] = "abc"
    assert r({"evidence": ev}) == "replan"
