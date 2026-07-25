"""terminal 工具:本地命令执行(用户要求全开——无白名单/黑名单)。

经 `bash -c` 执行,支持管道/重定向/复合命令;保留强制超时 + 受限工作目录 + 捕获 stdout/stderr/rc,
输出截断防爆上下文。agent 可自由用系统 CLI:decompyle3/uncompyle6(反编译 pyc)、
pyinstxtractor-ng(解 PyInstaller)、upx、binwalk、objdump/nm/readelf、strings|grep 等。
"""
from __future__ import annotations

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated


def terminal(command: str, workdir=None, timeout=None) -> dict:
    """执行任意本地 shell 命令(无白名单/黑名单,用户要求全开)。

    经 `bash -c` 跑,支持管道/重定向/&&/$() 等 shell 特性;仅保留超时 + 工作目录隔离防卡死。
    """
    if not command or not command.strip():
        return {"returncode": 1, "stdout": "", "stderr": "空命令", "timed_out": False}
    r = run_isolated(
        ["bash", "-c", command],
        timeout=timeout or config.TERMINAL_TIMEOUT,
        cwd=str(workdir) if workdir else None,
    )
    return {
        "returncode": r.returncode,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "timed_out": r.timed_out,
    }
