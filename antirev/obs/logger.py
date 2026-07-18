"""双轨日志(§10):

- JSONL(每行一事件):机器可解析,用于回放/复盘/优化 prompt。含 ts/run_id/type + 任意字段。
- .log(人类可读):赛场实时观察。长输出用"见记忆库 fn#N"引用,不落全文,与上下文策略一致。
"""
from __future__ import annotations
import datetime
import json
from pathlib import Path


def _utc_now_iso() -> str:
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


class RunLogger:
    def __init__(self, run_id: str, log_dir):
        self.run_id = run_id
        d = Path(log_dir)
        d.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = d / f"{run_id}.jsonl"
        self.human_path = d / f"{run_id}.log"

    def event(self, type: str, **fields) -> None:
        """写一条机器可读事件。type 如 tool_call/tool_result/executor_thought/replan/flag_found。"""
        rec = {"ts": _utc_now_iso(), "run_id": self.run_id, "type": type, **fields}
        with self.jsonl_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def human_line(self, text: str) -> None:
        """写一行人类可读日志。"""
        with self.human_path.open("a", encoding="utf-8") as f:
            f.write(text + "\n")
