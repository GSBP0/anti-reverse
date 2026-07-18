"""LangGraph 全局状态(§3):题目信息 / Plan / 进度 / flag 在节点间流转。"""
from __future__ import annotations
from typing import TypedDict


class AgentState(TypedDict, total=False):
    binary: str
    pre_analysis: dict        # 确定性预分析(file_info/packer/strings)
    plan: str                 # Planner 产出的 Plan
    executor_result: dict     # Executor 一轮的结果
    evidence: list            # 跨重规划累积的证据(已试/已排除)
    flag: str
    replan_count: int
    status: str               # planning / executing / done / stuck / failed
