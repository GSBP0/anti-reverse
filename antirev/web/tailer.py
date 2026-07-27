"""jsonl 增量读取:按字节 offset 续读,缓冲不完整行,行号即 seq。

为什么必须按**字节**缓冲:agent 用 append 模式逐行写(obs/logger.py:28),tool_result
的 obs 动辄上 MB,单次 write 不保证原子。若先 decode 再按字符缓冲,一个跨 chunk 边界
的多字节字符会被 errors="replace" 换成 U+FFFD 永久损坏那一行。
"""
from __future__ import annotations
import json
import os

OBS_LIMIT = 2048          # 摘要上限:**字符**数(不是字节 —— 中文按字节截会切坏 UTF-8 码点)
# 会长到需要截断的字段。截断只影响 SSE 摘要,全文永远可用 read_event 拉回。
TRUNC_KEYS = ("obs", "plan", "thought", "hint", "error", "summary", "ledger", "decompiles")


def _trunc_value(v, limit: int):
    """截断任意结构里的长字符串,返回 (新值, 原始字符总数)。

    必须递归:真实 agent 的 tool_result.obs **是 dict 而非字符串**
    (`ida_decompile` → {'pseudocode':…,'data_refs':…}、`run_python` → {'stdout':…,'stderr':…}),
    只判 isinstance(v, str) 会让 dict 型 obs 完全绕过截断 —— 等于没有体积上限。
    保留结构不整体序列化,因为前端要靠 key 名决定怎么渲染。
    """
    if isinstance(v, str):
        return (v[:limit] if len(v) > limit else v), len(v)
    if isinstance(v, dict):
        out, total = {}, 0
        for k, sub in v.items():
            out[k], n = _trunc_value(sub, limit)
            total += n
        return out, total
    if isinstance(v, list):
        out, total = [], 0
        for sub in v:
            nv, n = _trunc_value(sub, limit)
            out.append(nv)
            total += n
        return out, total
    return v, 0


class JsonlTailer:
    """一个文件一个实例,记住已消费的字节位置。非线程安全(每个 SSE 连接独立持有)。"""

    def __init__(self, path, obs_limit: int = OBS_LIMIT):
        self.path = str(path)
        self.obs_limit = obs_limit
        self.offset = 0        # 已消费的字节位置
        self.seq = 0           # 已扫过的行号(1-based,含坏行)
        self._buf = b""        # 不完整行的字节缓冲
        self.bad_lines = 0     # 坏 JSON 计数(只统计,不掐断流)

    def poll(self) -> list:
        """读出自上次以来的完整行,返回规范化事件 list。文件不存在 → []。"""
        try:
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                chunk = f.read()
                self.offset = f.tell()
        except FileNotFoundError:
            return []
        if not chunk:
            return []
        self._buf += chunk
        out = []
        while b"\n" in self._buf:
            raw, self._buf = self._buf.split(b"\n", 1)
            if not raw.strip():
                continue
            self.seq += 1
            ev = self._normalize(raw.decode("utf-8", errors="replace"), self.seq)
            if ev is not None:
                out.append(ev)
        return out

    def at_eof(self) -> bool:
        """已消费到文件末尾且无半行残留。SSE 用它判定"这个历史 run 推完了,可以收流"。"""
        try:
            return self.offset >= os.path.getsize(self.path) and not self._buf
        except OSError:
            return True                 # 文件都不在,当然没有更多内容

    def _normalize(self, line: str, seq: int):
        try:
            rec = json.loads(line)
        except Exception:
            self.bad_lines += 1
            return None                 # 坏行跳过但占用 seq,保证 seq 恒等于真实行号
        ev = {"seq": seq, **rec}
        for k in TRUNC_KEYS:
            if k not in ev:
                continue
            newv, total = _trunc_value(ev[k], self.obs_limit)
            if total > self.obs_limit:
                ev[k] = newv
                ev.setdefault("_truncated", []).append(k)
                ev[f"_{k}_len"] = total      # 原始字符总数(dict 型是内部所有字符串之和)
        return ev


def read_event(path, seq: int, offset: int = 0, limit: int = 262144):
    """按 seq(行号)取某条事件全文,对长字段分页。单次上限 256KB,防前端拉爆。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if i != seq:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    return None
                for k in TRUNC_KEYS:
                    if isinstance(rec.get(k), str):
                        rec[k] = rec[k][offset: offset + limit]
                rec["seq"] = seq
                return rec
    except FileNotFoundError:
        return None
    return None
