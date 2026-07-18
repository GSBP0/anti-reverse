from antirev.pipeline_mvp import run_pipeline


def test_mvp_end_to_end_recovers_and_verifies_flag(sample, expected_flag):
    """★MVP 核心里程碑★:无模型下 decompile→locate→angr→verify 端到端出 flag 并回验。"""
    r = run_pipeline(sample, stdin_len=len(expected_flag))
    assert r["flag"] is not None, r
    assert expected_flag in r["flag"]
    assert r["verified"] is True, r
