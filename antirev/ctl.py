"""Web 控制平面的 agent 侧契约:只认 logs/<run_id>.ctl 这一个文件。

刻意放在 antirev/web/ 外面 —— agent 不该 import 任何 web 层代码。Web 后端与
agent 之间唯一的耦合就是这个文件的格式。

设计依据: docs/superpowers/specs/2026-07-27-antirev-web-console-design.md §4
"""
from __future__ import annotations
import json
import signal
import time
from pathlib import Path

from antirev import config

POLL_INTERVAL = 0.3                                  # 暂停时的轮询间隔(秒)
_STATES = ("running", "paused", "stopping")


class StopRequested(BaseException):
    """人工停止请求。

    **刻意继承 BaseException**:react_executor.py:679 的 `except Exception: continue`
    会吞掉普通 Exception,让停止请求退化成"跳过一步继续跑"。继承 BaseException 才能
    穿过它、直达 run() 的 finally(:683)走完 store.close() + _close_ida() 清理。
    """


def ctl_path(run_id: str) -> Path:
    return Path(config.LOG_DIR) / f"{run_id}.ctl"


def read_state(run_id: str) -> str:
    """读控制状态。文件缺失/损坏/取值非法 → "running"。

    默认放行是刻意的:控制面故障绝不能把 agent 卡死在暂停里。
    """
    try:
        st = json.loads(ctl_path(run_id).read_text()).get("state")
    except Exception:
        return "running"
    return st if st in _STATES else "running"


def read_pid(run_id: str) -> int | None:
    try:
        pid = json.loads(ctl_path(run_id).read_text()).get("pid")
        return int(pid) if pid else None
    except Exception:
        return None


def write_state(run_id: str, state: str, pid: int | None = None) -> None:
    """写控制状态(Web 后端用;agent 侧只读)。不传 pid 时保留已有的。"""
    if state not in _STATES:
        raise ValueError(f"非法状态 {state},只能是 {_STATES}")
    p = ctl_path(run_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    rec = {"state": state, "ts": round(time.time(), 1)}
    if pid is not None:
        rec["pid"] = pid
    else:
        old = read_pid(run_id)      # 状态切换不擦 pid:Web 重启要靠它接管孤儿 run
        if old:
            rec["pid"] = old
    p.write_text(json.dumps(rec))
