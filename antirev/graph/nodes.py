"""Planner 节点(§3.2)与 Executor 节点(§3.3)。依赖(client/logger)由 build.py 经闭包注入。

- Planner:先跑确定性预分析(file_info/detect_packer/strings,§5.3),再让模型判题型 + 产出 Plan。
- Executor:用 Plan + 预分析事实做初始输入,跑自研 ReAct Executor(不开 thinking,§3.3)。
- 重规划:Executor 未出 flag → 回 Planner,带上本轮证据重新规划(§3.4)。
"""
from __future__ import annotations
import json
import time

from antirev.react_executor import ReactExecutor
from antirev.tools import analyze_tools as A

PLANNER_SYS = (
    "你是逆向题的 Planner。根据确定性预分析判断**题型**并产出简短分步 Plan。\n"
    "题型参考:flag校验 / 加密(异或/TEA/XTEA/XXTEA/RC4/AES/base64/移位) / VM混淆 / 加壳 / 反调试 / 运行时解密。\n"
    "Plan 要点(简洁,不啰嗦):主类型、架构、关键线索、分步(每步目标+建议工具+成功判据)、flag格式。"
)

_HINT_KW = ("flag", "nssctf", "correct", "wrong", "right", "input", "key",
            "enc", "cipher", "tea", "xtea", "rc4", "aes", "base64", "{")


def _pre_analyze(binary) -> dict:
    fi = A.file_info(binary)
    pk = A.detect_packer(binary)
    strs = A.ascii_strings(binary, min_len=5, limit=200)
    hints = [s for s in strs if any(k in s.lower() for k in _HINT_KW)][:25]
    return {"file_info": fi, "packer": pk, "hint_strings": hints, "num_strings": len(strs)}


def _fmt_pre(pre) -> str:
    return json.dumps(pre, ensure_ascii=False, indent=1)


def make_planner(client, logger=None):
    def planner_node(state):
        binary = state["binary"]
        pre = state.get("pre_analysis") or _pre_analyze(binary)
        replan = state.get("replan_count", 0)
        parts = [f"## 确定性预分析\n{_fmt_pre(pre)}"]
        if replan and state.get("evidence"):
            last = state["evidence"][-1]
            trace = last.get("trace") or []
            parts.append(f"\n## 第{replan}次重规划:上一轮({last.get('steps')}步)未解出。\n"
                         f"上一轮做过的步骤:\n" + "\n".join(f"  {t}" for t in trace[-15:]))
            parts.append("请**换一个不同的思路/工具/参数**改进计划(别重复上一轮的失败路径)。"
                         "如密码题解出乱码→换 endian/rounds;angr 超时→改读算法写 run_python;"
                         "找不到函数→ida_list_functions;数据读错→按 data_refs 真实地址。")
        parts.append("\n据此判断题型并产出 Plan。")
        plan = client.complete([{"role": "system", "content": PLANNER_SYS},
                                {"role": "user", "content": "\n".join(parts)}], max_tokens=900)
        if logger:
            logger.event("plan_md", replan=replan, plan=plan[:2000])
        return {"pre_analysis": pre, "plan": plan, "status": "executing"}
    return planner_node


def make_executor(client, logger=None, max_steps=25, deadline=None, db_path=None,
                  stuck_seconds=None, progress=None):
    def executor_node(state):
        binary = state["binary"]
        remaining = (deadline - time.time()) if deadline else None
        if remaining is not None and remaining <= 5:      # 全局预算用尽
            return {"status": "stuck", "replan_count": state.get("replan_count", 0) + 1}
        task = (f"题目文件: {binary}\n\n## 预分析\n{_fmt_pre(state.get('pre_analysis', {}))}\n\n"
                f"## Plan\n{state.get('plan', '')}\n\n按 Plan 解出 flag,拿到后用 FINAL 输出。")
        ex = ReactExecutor(binary, client=client, logger=logger, max_steps=max_steps,
                           time_budget=remaining, db_path=db_path,   # 跨轮共享缓存 db_path
                           stuck_seconds=stuck_seconds, progress=progress)  # 跨轮共享 stuck 追踪
        result = ex.run(task)
        ev = list(state.get("evidence", []))
        ev.append({"replan": state.get("replan_count", 0), "steps": result.get("steps"),
                   "flag": result.get("flag"), "trace": result.get("trace"),
                   "last_state": result.get("state")})
        upd = {"executor_result": result, "evidence": ev}
        if result.get("flag"):
            upd["flag"], upd["status"] = result["flag"], "done"
        else:
            upd["status"] = "stuck"
            upd["replan_count"] = state.get("replan_count", 0) + 1
        return upd
    return executor_node


def make_router(max_replan=9, deadline=None, stuck_seconds=None, progress=None):
    def route_after_executor(state):
        if state.get("flag"):
            return "done"
        if deadline and time.time() > deadline:      # 全局时间预算到点
            return "fail"
        if stuck_seconds and progress and time.time() - progress.get("last", time.time()) > stuck_seconds:
            return "fail"                            # 10min无新进展,提前判失败
        if state.get("replan_count", 0) <= max_replan:
            return "replan"
        return "fail"
    return route_after_executor
