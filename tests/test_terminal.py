from antirev.tools.terminal import terminal


def test_runs_and_captures(tmp_path):
    r = terminal("echo hello", workdir=tmp_path)
    assert r["returncode"] == 0
    assert "hello" in r["stdout"]
    assert r["timed_out"] is False


def test_timeout_flagged(tmp_path):
    r = terminal("sleep 5", workdir=tmp_path, timeout=1)
    assert r["timed_out"] is True


def test_nonzero_returncode(tmp_path):
    r = terminal("false", workdir=tmp_path)
    assert r["returncode"] != 0
    assert r["timed_out"] is False
