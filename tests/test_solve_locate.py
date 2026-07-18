def test_locate_finds_success_and_fail(targets):
    assert targets["find"], "应从 'Correct' 串反推出成功分支地址"
    assert targets["avoid"], "应从 'Wrong' 串反推出失败分支地址"
    assert all(isinstance(x, int) for x in targets["find"] + targets["avoid"])


def test_find_and_avoid_are_distinct(targets):
    assert set(targets["find"]).isdisjoint(set(targets["avoid"]))


def test_evidence_records_strings(targets):
    kinds = {e["kind"] for e in targets["evidence"]}
    assert "success" in kinds and "fail" in kinds
