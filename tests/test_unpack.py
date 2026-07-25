"""C2.2 通用脱壳单测(纯函数必测,unicorn 重活 skipif)。"""
from antirev.tools.unpack import _looks_like_oep, generic_unpack


def test_looks_like_oep_positive():
    # 写过的页 0x2000、不在壳入口节区 [0x1000,0x2000)、执行超 2000 条 → 疑似 OEP
    assert _looks_like_oep(0x2000, {0x2000}, (0x1000, 0x2000), 3000) is True


def test_looks_like_oep_in_entry_section():
    assert _looks_like_oep(0x1500, {0x1000, 0x2000}, (0x1000, 0x2000), 3000) is False


def test_looks_like_oep_too_early():
    assert _looks_like_oep(0x2000, {0x2000}, (0x1000, 0x2000), 100) is False


def test_looks_like_oep_page_not_written():
    assert _looks_like_oep(0x3000, {0x2000}, (0x1000, 0x2000), 3000) is False


def test_generic_unpack_missing_file_graceful():
    r = generic_unpack("/nonexistent/xyz_no_such.exe")
    assert isinstance(r, dict) and r.get("ok") is False      # 优雅降级、不抛穿
