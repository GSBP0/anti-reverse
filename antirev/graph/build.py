"""LangGraph StateGraph 组装(§3.1):Planner → Executor →(卡住重规划 / 出flag结束)。

循环机制(§3.4):
- 全局时间预算跨轮共享 —— 每轮 executor 拿"剩余时间",router 到点即止(不再每轮各吃满预算)。
- 跨轮共享 SQLite 缓存 —— 重规划时 IDA 分析命中缓存,replan 便宜,10 轮才跑得动。
- Executor 把执行轨迹回传,Planner 据此换思路重规划(而非重复)。
"""
from __future__ import annotations
import time
from pathlib import Path

from langgraph.graph import StateGraph, END

from antirev import config
from antirev.react_executor import ChatClient
from antirev.graph.state import AgentState
from antirev.graph.nodes import make_planner, make_executor, make_router


def build_graph(client, logger=None, max_replan=9, max_steps=15, deadline=None, db_path=None,
                stuck_seconds=None, progress=None):
    g = StateGraph(AgentState)
    g.add_node("planner", make_planner(client, logger))
    g.add_node("executor", make_executor(client, logger, max_steps, deadline, db_path,
                                         stuck_seconds, progress))
    g.set_entry_point("planner")
    g.add_edge("planner", "executor")
    g.add_conditional_edges("executor", make_router(max_replan, deadline, stuck_seconds, progress),
                            {"done": END, "replan": "planner", "fail": END})
    return g.compile()


def solve(binary, client=None, logger=None, max_replan=9, max_steps=15, budget=None, stuck_seconds=None):
    """双 Agent 端到端解一道题(最多 max_replan+1 轮 planner↔executor)。返回 {flag,status,replans,plan}。"""
    client = client or ChatClient()
    deadline = (time.time() + budget) if budget else None
    progress = {"last": time.time(), "seen": set()}   # 跨轮共享进展追踪(stuck 检测用)
    run_id = getattr(logger, "run_id", None) or "solve"
    db_path = str(config.LOG_DIR / f"{run_id}.db")   # 跨轮共享缓存(IDA分析不重复)
    Path(db_path).unlink(missing_ok=True)             # 每次求解清旧缓存
    app = build_graph(client, logger, max_replan, max_steps, deadline, db_path, stuck_seconds, progress)
    final = app.invoke({"binary": str(binary), "replan_count": 0, "evidence": []},
                       {"recursion_limit": 2 * (max_replan + 2) + 4})
    return {"flag": final.get("flag"), "status": final.get("status"),
            "replans": final.get("replan_count", 0), "plan": final.get("plan")}
