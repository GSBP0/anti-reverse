"""flag_check 校验工具单测:前缀无关比对 + 三态判决 + 噪声容忍。

针对 R21 回归暴露的评估失灵设计的回归防线:
- 前缀无关:NSSCTF 收录改写(HDCTF→NSSCTF)不该把正确解误杀。
- 三态:无 truth 的题必须判 no_truth(不计入对错),不能像旧 score 一样恒 False。
"""
from antirev.flag_check import check, verdict_only, _inner, _norm

DB = {
    "1": {"flag": "HDCTF{y0u_ar3_master}", "aliases": []},
    "2": {"flag": "NSSCTF{abc}", "aliases": ["flag{abc}"]},
    "3": {"flag": "LitCTF{B@5E64_l5_tooo0_E3sy!!!!!}", "aliases": []},
}


def test_prefix_agnostic():
    # 前缀无关:NSSCTF 改写版对上原 HDCTF(救 3790 类误杀)
    assert check("NSSCTF{y0u_ar3_master}", "1", DB)[0] == "correct"
    assert check("HDCTF{y0u_ar3_master}", "1", DB)[0] == "correct"


def test_exact_match():
    assert check("NSSCTF{abc}", "2", DB)[0] == "correct"


def test_special_chars_in_flag():
    # 花括号内含 @/!/数字等特殊字符(救 3846 的 B@5E64)
    assert check("NSSCTF{B@5E64_l5_tooo0_E3sy!!!!!}", "3", DB)[0] == "correct"


def test_wrong():
    assert check("HDCTF{wrong_content}", "1", DB)[0] == "wrong"


def test_empty_flag_with_truth_is_wrong():
    # 有标准答案但没交 flag = 答错(不是 no_truth)
    assert check("", "1", DB)[0] == "wrong"
    assert check(None, "1", DB)[0] == "wrong"


def test_no_truth():
    # 库里没这题 → 无法判定,不计入对错(救 truth 缺失被误判为 wrong)
    assert check("anything", "999", DB)[0] == "no_truth"
    assert check("NSSCTF{whatever}", "999", DB)[0] == "no_truth"


def test_noise_tolerant():
    # 排版噪声:首尾空白、内部空格、大小写
    assert check("  HDCTF{ y0u_ar3_master }  ", "1", DB)[0] == "correct"
    assert check("hdctf{Y0U_AR3_MASTER}", "1", DB)[0] == "correct"


def test_alias_match():
    assert check("flag{abc}", "2", DB)[0] == "correct"


def test_verdict_only():
    assert verdict_only("HDCTF{y0u_ar3_master}", "1", DB) == "correct"
    assert verdict_only("x", "999", DB) == "no_truth"


def test_inner_outermost_braces():
    # 取最外层花括号(嵌套时不截断)
    assert _inner("flag{abc}") == "abc"
    assert _inner("flag{a{b}c}") == "a{b}c"
    assert _inner("no_braces_here") == "no_braces_here"


def test_norm():
    assert _norm("  `Flag`  ") == "flag"
    assert _norm("A B\tC") == "abc"
