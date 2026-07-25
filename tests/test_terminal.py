"""terminal 全开(无白名单/黑名单)单测:任意 shell 命令 + 管道/重定向,仅保留超时防卡死。"""
from antirev.tools.terminal import terminal


def test_runs_arbitrary_command(tmp_path):
    # 全开:任意命令都能跑(echo 之前被白名单拒,现在放行)
    r = terminal("echo hello", workdir=tmp_path)
    assert r["returncode"] == 0
    assert "hello" in r["stdout"]
    assert r["timed_out"] is False


def test_shell_pipe_and_compound(tmp_path):
    # bash -c:支持管道 + && 复合
    r = terminal("echo abc | grep abc && echo ok", workdir=tmp_path)
    assert r["returncode"] == 0
    assert "ok" in r["stdout"]


def test_redirect_writes_file(tmp_path):
    # 重定向改文件(全开允许,不再限只读)
    r = terminal("echo data > out.txt && cat out.txt", workdir=tmp_path)
    assert r["returncode"] == 0
    assert "data" in r["stdout"]


def test_no_whitelist_rejection(tmp_path):
    # 之前被白名单拒的命令(echo/sleep/rm 类)现在都不再 rejected
    for cmd in ("echo hi", "true", "ls -la"):
        r = terminal(cmd, workdir=tmp_path)
        assert not r.get("rejected")


def test_timeout_still_enforced(tmp_path):
    # 超时仍生效(防卡死)——唯一保留的护栏
    r = terminal("sleep 5", workdir=tmp_path, timeout=1)
    assert r["timed_out"] is True


def test_nonzero_returncode(tmp_path):
    r = terminal("false", workdir=tmp_path)
    assert r["returncode"] != 0
    assert r["timed_out"] is False


def test_empty_command(tmp_path):
    r = terminal("", workdir=tmp_path)
    assert r["returncode"] == 1
