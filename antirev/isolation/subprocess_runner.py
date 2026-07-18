"""一次性受管子进程:超时 → 杀整个进程组;捕获 stdout/stderr/rc;绝不把异常抛穿主循环。

敌意样本会让工具进程崩溃/挂死(§2/§11),所以所有重工具(IDA/angr/terminal)都经此运行:
- start_new_session=True 让子进程独立成组,超时时 killpg 连子孙一起杀,防逃逸。
- 任何 spawn/超时/崩溃都转成结构化结果,主 Agent 循环拿到"工具失败"观察后继续决策。
"""
from __future__ import annotations
import os
import signal
import subprocess
from dataclasses import dataclass


@dataclass
class IsolatedResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool


def run_isolated(cmd, timeout, cwd=None, env=None, input_text=None) -> IsolatedResult:
    """在受管子进程里跑 cmd(list[str]),带超时。

    超时会 SIGKILL 整个进程组。返回 IsolatedResult,永不抛出(除非调用参数本身非法)。
    """
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=env,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,  # 独立进程组,便于整组回收
        )
    except (FileNotFoundError, OSError) as e:
        return IsolatedResult(127, "", f"spawn failed: {e!r}", False)

    try:
        out, err = proc.communicate(input=input_text, timeout=timeout)
        return IsolatedResult(proc.returncode, out or "", err or "", False)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = "", ""
        return IsolatedResult(-signal.SIGKILL, out or "", err or "", True)


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
