"""terminal 工具(§5.4):杂项兜底命令执行。

边界:angr/z3/unicorn/floss/DIE 都是一等厚工具,**不走**这里裸调;terminal 只用于临时
xxd/strings/自定义脚本等。强制超时 + 受限工作目录 + 捕获 stdout/stderr/rc,输出截断防爆上下文。
"""
from __future__ import annotations
import shlex

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated


def terminal(command: str, workdir=None, timeout=None) -> dict:
    """执行本地命令。command 为 shell 风格字符串(经 shlex 拆分,不走 shell 注入路径)。"""
    r = run_isolated(
        shlex.split(command),
        timeout=timeout or config.TERMINAL_TIMEOUT,
        cwd=str(workdir) if workdir else None,
    )
    return {
        "returncode": r.returncode,
        "stdout": r.stdout[-4000:],
        "stderr": r.stderr[-2000:],
        "timed_out": r.timed_out,
    }
