"""共享 fixture:样本二进制 + 动态求得的 find/avoid 目标(不手工回填地址)。"""
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = str(ROOT / "tests/samples/flagcheck")
MAKE = str(ROOT / "tests/samples/make_sample.py")
EXPECTED_FLAG = "flag{unic0rn_x0r}"


def _ensure_sample():
    if not Path(SAMPLE).exists():
        subprocess.run([sys.executable, MAKE, SAMPLE], cwd=str(ROOT), check=True)


def pytest_configure(config):
    _ensure_sample()


@pytest.fixture(scope="session")
def sample():
    _ensure_sample()
    return SAMPLE


@pytest.fixture(scope="session")
def expected_flag():
    return EXPECTED_FLAG


@pytest.fixture(scope="session")
def targets(sample):
    """确定性推导的 {find, avoid, evidence}。多个 solve 测试复用,避免重复分析。"""
    from antirev.tools.solve_locate import locate_targets
    return locate_targets(sample)
