"""SQLite 外部记忆层(§6.3):存全量(反编译/字节/中间结论),上下文只放引用+摘要。

本质是对二进制做 RAG:大段输出进 SQLite,Working Memory 里只留"摘要 + artifact#id",
需要重看时按 id recall。同时做工具缓存:同 (tool,args) 命中直接取,避免重复反编译。
"""
from __future__ import annotations
import json
import sqlite3
import time
from pathlib import Path


def _canon(args) -> str:
    return json.dumps(args or {}, ensure_ascii=False, sort_keys=True)


class MemoryStore:
    def __init__(self, db_path=":memory:"):
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS artifacts(
                id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, tool TEXT,
                args_json TEXT, summary TEXT, full_text TEXT, created REAL);
            CREATE TABLE IF NOT EXISTS facts(
                id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT, key TEXT,
                value TEXT, step INTEGER);
            CREATE INDEX IF NOT EXISTS idx_art_cache ON artifacts(run_id, tool, args_json);
            """
        )
        self.conn.commit()

    def put_artifact(self, run_id, tool, args, summary, full_text) -> int:
        cur = self.conn.execute(
            "INSERT INTO artifacts(run_id,tool,args_json,summary,full_text,created) "
            "VALUES(?,?,?,?,?,?)",
            (run_id, tool, _canon(args), summary, full_text, time.time()))
        self.conn.commit()
        return cur.lastrowid

    def get_artifact(self, artifact_id) -> dict | None:
        row = self.conn.execute(
            "SELECT tool,args_json,summary,full_text FROM artifacts WHERE id=?",
            (artifact_id,)).fetchone()
        if not row:
            return None
        return {"id": artifact_id, "tool": row[0], "args": json.loads(row[1]),
                "summary": row[2], "full_text": row[3]}

    def list_artifacts(self, run_id) -> list:
        """按时序列出本 run 的所有工具调用(含全文 obs),供跨轮重建台账(§6 结构化记忆)。"""
        rows = self.conn.execute(
            "SELECT id,tool,args_json,summary,full_text FROM artifacts WHERE run_id=? ORDER BY id",
            (run_id,)).fetchall()
        return [{"id": i, "tool": t, "args": json.loads(a or "{}"),
                 "summary": s, "full_text": f} for (i, t, a, s, f) in rows]

    def find_cached(self, run_id, tool, args) -> dict | None:
        row = self.conn.execute(
            "SELECT id,summary,full_text FROM artifacts "
            "WHERE run_id=? AND tool=? AND args_json=? ORDER BY id DESC LIMIT 1",
            (run_id, tool, _canon(args))).fetchone()
        if not row:
            return None
        return {"id": row[0], "summary": row[1], "full_text": row[2]}

    def put_fact(self, run_id, key, value, step=None) -> None:
        self.conn.execute("INSERT INTO facts(run_id,key,value,step) VALUES(?,?,?,?)",
                          (run_id, key, str(value), step))
        self.conn.commit()

    def get_facts(self, run_id) -> list:
        return [{"key": k, "value": v, "step": s} for (k, v, s) in self.conn.execute(
            "SELECT key,value,step FROM facts WHERE run_id=? ORDER BY id", (run_id,)).fetchall()]

    def contains(self, run_id, needle) -> bool:
        """needle 是否在本 run 任一工具输出全文里出现过(反假阳性:flag 必须有工具佐证)。"""
        if not needle:
            return False
        for (t,) in self.conn.execute(
                "SELECT full_text FROM artifacts WHERE run_id=?", (run_id,)):
            if needle in (t or ""):
                return True
        return False

    def close(self) -> None:
        self.conn.close()
