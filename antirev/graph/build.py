"""LangGraph StateGraph 组装(§3.1):Planner → Executor →(卡住重规划 / 出flag结束)。

用 LangGraph 而非裸循环:显式状态图 + 条件边表达"收集→规划→执行→卡住→重规划→结束",
可持久化/断点(checkpointer),上下文完全可控。
"""
from __future__ import annotations

from langgraph.graph import StateGraph, END

from antirev.react_executor import ChatClient
from antirev.graph.state import AgentState
from antirev.graph.nodes import make_planner, make_executor, make_router


def build_graph(client, logger=None, max_replan=2, max_steps=60):
    g = StateGraph(AgentState)
    g.add_node("planner", make_planner(client, logger))
    g.add_node("executor", make_executor(client, logger, max_steps))
    g.set_entry_point("planner")
    g.add_edge("planner", "executor")
    g.add_conditional_edges("executor", make_router(max_replan),
                            {"done": END, "replan": "planner", "fail": END})
    return g.compile()


def solve(binary, client=None, logger=None, max_replan=2, max_steps=60):
    """双 Agent 端到端解一道题。返回 {flag, status, replans, plan}。"""
    client = client or ChatClient()
    app = build_graph(client, logger, max_replan, max_steps)
    final = app.invoke({"binary": str(binary), "replan_count": 0, "evidence": []},
                       {"recursion_limit": 50})
    return {"flag": final.get("flag"), "status": final.get("status"),
            "replans": final.get("replan_count", 0), "plan": final.get("plan")}
