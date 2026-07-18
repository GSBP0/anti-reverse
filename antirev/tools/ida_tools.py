"""py3.12 侧 IDA 厚工具:把 idalib worker(py3.14)拉成常驻子进程,JSON 逐行往返。

- 版本隔离:主环境是 py3.12(angr 生态),IDA 的 IDAPython 是 cp314;二者经进程 + 协议解耦。
- 崩溃/超时隔离:worker 独立进程组,select 读超时即杀,不拖垮主循环(§5.5/§11)。
- 压缩切片(原则4):decompile 一次一个函数;strings/xrefs 只回地址+名,全量不进上下文。
"""
from __future__ import annotations
import json
import os
import select
import signal
import subprocess
from pathlib import Path

from antirev import config

WORKER = str(Path(__file__).with_name("ida_worker.py"))


class IdaError(RuntimeError):
    pass


class IdaSession:
    """用法:
        with IdaSession(binary) as ida:
            ida.list_functions()
            ida.decompile("main")     # 名或 "0x401080"
            ida.xrefs_to(0x400105)
    """

    def __init__(self, binary, py314=None, query_timeout=None, analysis_timeout=None):
        self.binary = str(Path(binary).resolve())
        self.py = str(py314 or config.IDA_PY314)
        self.query_timeout = query_timeout or config.IDA_QUERY_TIMEOUT
        self.analysis_timeout = analysis_timeout or config.IDA_ANALYSIS_TIMEOUT
        self.p = None
        self.ready = None

    def __enter__(self):
        if not Path(self.py).exists():
            raise IdaError(f"IDA py3.14 解释器不存在: {self.py}(见 config.IDA_PY314)")
        self.p = subprocess.Popen(
            [self.py, WORKER, self.binary],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, start_new_session=True,
        )
        ready = self._readline(self.analysis_timeout)  # 等自动分析完成
        if not ready.get("ok"):
            self._kill()
            raise IdaError(f"IDA worker init 失败: {ready}")
        self.ready = ready["result"]
        return self

    def __exit__(self, *exc):
        try:
            if self.p and self.p.poll() is None:
                try:
                    self._send({"cmd": "close"})
                    self.p.wait(timeout=5)
                except Exception:
                    pass
        finally:
            self._kill()

    def _kill(self):
        if self.p and self.p.poll() is None:
            try:
                os.killpg(os.getpgid(self.p.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def _send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def _readline(self, timeout):
        r, _, _ = select.select([self.p.stdout], [], [], timeout)
        if not r:
            self._kill()
            raise IdaError(f"IDA worker 读超时({timeout}s)")
        line = self.p.stdout.readline()
        if not line:
            err = self.p.stderr.read() if self.p.stderr else ""
            raise IdaError(f"IDA worker 意外退出: {err[-600:]}")
        return json.loads(line)

    def _rpc(self, cmd, **args):
        self._send({"cmd": cmd, "args": args})
        resp = self._readline(self.query_timeout)
        if not resp.get("ok"):
            raise IdaError(f"ida {cmd} 出错: {resp.get('error')}")
        return resp["result"]

    # —— 厚工具(压缩切片) ——
    def list_functions(self, name_filter=None):
        fns = self._rpc("list_functions")
        if name_filter:
            fns = [f for f in fns if name_filter in (f["name"] or "")]
        return fns

    def entry_ea(self):
        return self._rpc("entry_ea")["addr"]

    def decompile(self, name_or_addr):
        return self._rpc("decompile", name_or_addr=name_or_addr)

    def strings(self, filter=None):
        return self._rpc("strings", filter=filter)

    def xrefs_to(self, addr):
        return self._rpc("xrefs_to", addr=int(addr))
