"""LangGraph 全局状态(§3):题目信息 / Plan / 进度 / flag 在节点间流转。"""
from __future__ import annotations
from typing import TypedDict


class AgentState(TypedDict, total=False):
    binary: str
    pre_analysis: dict        # 确定性预分析(file_info/packer/strings)
    plan: str                 # Planner 产出的 Plan(渲染后的文本)
    plan_steps: list          # emit_plan 的结构化 steps,供 executor 尾部 TODO 复述
    executor_result: dict     # Executor 一轮的结果
    evidence: list            # 跨重规划累积的证据(已试/已排除)
    flag: str
    replan_count: int
    status: str               # planning / executing / done / stuck / failed
