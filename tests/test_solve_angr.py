from antirev.tools.solve_angr import solve_angr


def test_angr_recovers_flag(sample, targets, expected_flag):
    r = solve_angr(sample, find=targets["find"], avoid=targets["avoid"],
                   input_kind="stdin", stdin_len=len(expected_flag))
    assert r.get("found") is True, r
    assert expected_flag in r["stdin"]


def test_angr_timeout_is_structured(sample, targets):
    # 超小超时 → 结构化返回 found=False,而非异常
    r = solve_angr(sample, find=targets["find"], avoid=targets["avoid"],
                   stdin_len=17, timeout=0.001)
    assert r["found"] is False
    assert "error" in r
