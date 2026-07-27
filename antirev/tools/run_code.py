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
from antirev.isolation.subprocess_runner import clip_output, run_isolated


_EMU_HELPER = (
    "import sys as _sys\n"
    f"_sys.path.insert(0, {str(config.PROJECT_ROOT)!r})\n"
    "def emulate(start, stop, input_hex='', input_reg='rdx', read_offset=0, read_size=None,\n"
    "            extra_regs=None, arch='x86_64'):\n"
    "    '''高层模拟(懒加载):跑 BINARY 自身逻辑绕过花指令/魔改。返回 {ok, output_hex, regs, ...}。\n"
    "    逐字节变换求逆:对 input 喂 00..ff 建 F 表, flag[i]=Finv[密文[i]]。数据用 pwn.ELF(BINARY).read(va,n) 读。'''\n"
    "    from antirev.tools.solve_unicorn import emulate_function as _emu\n"
    "    return _emu(BINARY, start, stop, input_hex=input_hex, input_reg=input_reg,\n"
    "                read_offset=read_offset, read_size=read_size, extra_regs=extra_regs, arch=arch)\n"
)


def run_python(code: str, binary: str = None, timeout: int = None, workdir: str = None) -> dict:
    # 护栏(bug:上下文压缩占位符 "<此前脚本已省略…>" 曾被模型当真代码回传→连环 SyntaxError,害 3265/751):
    # 检测到 code 其实是压缩占位串就拒绝、提示重发完整脚本,而不是拿它去执行。
    _c = (code or "").lstrip()
    if _c.startswith("<") and ("此前脚本已省略" in _c[:120] or "只保留最近" in _c[:120] or "脚本已省略" in _c[:120]):
        return {"returncode": 1, "stdout": "",
                "stderr": "[run_python 护栏] 传入的 code 是上下文压缩占位符、不是真实脚本,已拒绝执行。"
                          "请重新写出完整的 Python 代码(别复制历史里的省略占位串)。",
                "timed_out": False}
    binary = str(Path(binary).resolve()) if binary else None   # 绝对路径:子进程cwd是题目目录,相对路径会失效
    preamble = (f"BINARY = {binary!r}\n" + _EMU_HELPER) if binary else ""
    fd, path = tempfile.mkstemp(suffix=".py", prefix="antirev_solve_")
    try:
        os.write(fd, (preamble + code).encode())
        os.close(fd)
        # cwd 用项目根:模型脚本若写相对路径(如 'data/..')也能解析(否则 cwd=题目目录时相对路径全失效)
        cwd = workdir or str(config.PROJECT_ROOT)
        r = run_isolated([sys.executable, path],
                         timeout=timeout or config.TERMINAL_TIMEOUT * 2, cwd=cwd)
        return {"returncode": r.returncode,
                "stdout": clip_output(r.stdout, what="stdout"),
                "stderr": clip_output(r.stderr, what="stderr"),
                "timed_out": r.timed_out}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
