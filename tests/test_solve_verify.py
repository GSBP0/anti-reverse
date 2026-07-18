from antirev.tools.solve_verify import verify_candidate


def test_true_flag_reaches_accept(sample, targets, expected_flag):
    r = verify_candidate(sample, expected_flag,
                         find=targets["find"][0], avoid=targets["avoid"][0])
    assert r["accepted"] is True
    assert r["method"] == "angr-concrete"


def test_wrong_flag_rejected(sample, targets):
    r = verify_candidate(sample, "flag{definitely_wrong!}",
                         find=targets["find"][0], avoid=targets["avoid"][0])
    assert r["accepted"] is False


def test_format_fallback_when_no_find(sample):
    r = verify_candidate(sample, "flag{abc}", find=None)
    assert r["method"] == "format-only"
    assert "warning" in r
