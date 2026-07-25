"""docker_run 离线单测:降级 / 三态判决 / 魔数选型全不依赖真实 docker(skipif/monkeypatch 兜底)。"""
import shutil

import pytest

from antirev.tools import docker_run as dr


def test_degrades_without_docker(monkeypatch):
    """docker 缺失 → ok=False、available=False、附降级建议;不触碰二进制。"""
    monkeypatch.setattr(dr.shutil, "which", lambda x: None)
    r = dr.docker_run("/nonexistent/bin")
    assert r["ok"] is False
    assert r["available"] is False
    assert "降级" in r["error"]


def test_verdict_three_state():
    assert dr._verdict("Congratulations Correct!", 0, False) == "right"
    assert dr._verdict("Wrong", 1, False) == "wrong"
    assert dr._verdict("", 139, False) == "crash"
    assert dr._verdict("", None, True) == "timeout"


def test_select_by_format():
    elf_amd64 = b"\x7fELF\x02" + b"\x00" * 13 + (0x3E).to_bytes(2, "little")
    assert dr._select(elf_amd64)[1] == "linux/amd64"
    assert dr._select(b"MZ" + b"\x00" * 62)[0] == "PE"


def test_cmd_has_interactive_flag(tmp_path, monkeypatch):
    """回归:docker 命令必须带 -i,否则容器 stdin 不挂载 → 喂进去的 flag 根本到不了程序
    (真实 bug:'喂 flag 验证'因此从未工作过,实测 echo X | docker run debian sh -c cat 无输出)。"""
    binp = tmp_path / "x"
    binp.write_bytes(b"\x7fELF\x02" + b"\x00" * 13 + (0x3E).to_bytes(2, "little") + b"\x00" * 64)
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False})()

    monkeypatch.setattr(dr.shutil, "which", lambda x: "/usr/bin/docker")
    monkeypatch.setattr(dr, "_ensure_image", lambda img: True)
    monkeypatch.setattr(dr, "run_isolated", fake_run)
    dr.docker_run(str(binp), stdin_hex="41")
    assert "-i" in seen["cmd"], "docker run 缺 -i:stdin 不会送达程序"


def test_argv_passed_to_runline(tmp_path, monkeypatch):
    """回归:args 必须拼进容器命令行——很多题 flag 走 argv[1](如 funnyre 的 cmp edi,2),只喂 stdin 永远失败。"""
    binp = tmp_path / "x"
    binp.write_bytes(b"\x7fELF\x02" + b"\x00" * 13 + (0x3E).to_bytes(2, "little") + b"\x00" * 64)
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": "", "timed_out": False})()

    monkeypatch.setattr(dr.shutil, "which", lambda x: "/usr/bin/docker")
    monkeypatch.setattr(dr, "_ensure_image", lambda img: True)
    monkeypatch.setattr(dr, "run_isolated", fake_run)
    dr.docker_run(str(binp), args=["flag{abc}"])
    assert "flag{abc}" in seen["cmd"][-1], "args 没进容器 runline"


def test_registry_schema_exposes_args():
    """回归:registry schema 必须暴露 args——只暴露 stdin_hex 时模型无法验证 argv 型题(2000 funnyre 因此 4 次调用全废)。"""
    from antirev.tools.registry import TOOLS_SCHEMA
    spec = next(t for t in TOOLS_SCHEMA if t["function"]["name"] == "docker_run")
    props = spec["function"]["parameters"]["properties"]
    assert "args" in props and "stdin_hex" in props


def test_success_keyword_get_flag():
    """回归:'you get flag!'(2000 正解输出)必须判 right——原关键词表只有 'you got' 匹配不上。"""
    assert dr._verdict("you get flag!", 0, False) == "right"


@pytest.mark.skipif(not shutil.which("docker"), reason="no docker")
def test_real_run(tmp_path):
    """有 docker 时占位:对不存在/垃圾输入也应优雅返回 dict,不抛异常。"""
    r = dr.docker_run(str(tmp_path / "nope"))
    assert isinstance(r, dict)
    assert "ok" in r
