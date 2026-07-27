"""控制面写入:.hint 追加 + .ctl 状态转换合法性。

.hint 为什么必须追加而不能覆盖:react_executor.py 里读 hint 的去重判据是
`_h not in ctx.user_hints`,而它读的是文件**全量内容**。覆盖写时,若第二条提示是
第一条的子串,`not in` 判为假 → 静默丢弃。带 `[#N 时间]` 前缀保证每行绝对唯一。
"""
from __future__ import annotations
import time
from pathlib import Path

from antirev import config, ctl

ACTION_TO_STATE = {"pause": "paused", "resume": "running", "stop": "stopping"}


def hint_path(run_id: str) -> Path:
    return Path(config.LOG_DIR) / f"{run_id}.hint"


def append_hint(run_id: str, text: str) -> str:
    """追加一条人工提示。返回写入的整行(含唯一前缀)。"""
    text = (text or "").strip()
    if not text:
        raise ValueError("提示不能为空")
    p = hint_path(run_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    n = len(p.read_text(errors="ignore").splitlines()) + 1 if p.exists() else 1
    line = f"[#{n} {time.strftime('%H:%M:%S')}] {text}"
    with p.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    return line


def read_hints(run_id: str) -> list:
    """已发出的提示(按顺序)。前端用它回显"我给过什么提示"。"""
    p = hint_path(run_id)
    if not p.exists():
        return []
    return p.read_text(errors="ignore").splitlines()


def apply_action(run_id: str, action: str) -> str:
    """把前端动作落成 .ctl 状态,返回新状态。stopping 是终态,不可回退。"""
    if action not in ACTION_TO_STATE:
        raise ValueError(f"未知动作 {action},只能是 {sorted(ACTION_TO_STATE)}")
    if ctl.read_state(run_id) == "stopping":
        raise ValueError("该 run 已在停止中,不可再改状态")
    state = ACTION_TO_STATE[action]
    ctl.write_state(run_id, state)
    return state
