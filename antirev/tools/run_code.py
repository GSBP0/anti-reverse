"""run_python:在受隔离子进程里执行模型写的 Python 解题脚本。

这是解"读懂算法→写逆运算"类题目(xor/编码/TEA/XTEA/RC4/…)的通用手段——angr 解不了这些,
人类也是读懂后写脚本逆推。主环境自带 pwntools/z3/capstone 等。带超时 + 崩溃隔离(§5.5)。
预置变量 BINARY 指向题目文件,脚本可直接读原始字节。
"""
from __future__ import annotations
import os
import sys
import tempfile
from pathlib import Path

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated


def run_python(code: str, binary: str = None, timeout: int = None, workdir: str = None) -> dict:
    preamble = f"BINARY = {str(binary)!r}\n" if binary else ""
    fd, path = tempfile.mkstemp(suffix=".py", prefix="antirev_solve_")
    try:
        os.write(fd, (preamble + code).encode())
        os.close(fd)
        cwd = workdir or (str(Path(binary).parent) if binary else None)
        r = run_isolated([sys.executable, path],
                         timeout=timeout or config.TERMINAL_TIMEOUT * 2, cwd=cwd)
        return {"returncode": r.returncode, "stdout": r.stdout[-6000:],
                "stderr": r.stderr[-2000:], "timed_out": r.timed_out}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
