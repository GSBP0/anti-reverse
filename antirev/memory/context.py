"""Executor 上下文管理(§6):Working Memory + 历史窗口 + 观察压缩 + 外部记忆引用。

目标(§6 核心):让上下文始终概括当前全部进度,且远低于 64k。做法:
- 只保留最近 window 步的**原始观察**;更早步压成一行摘要进 Working Memory(§6.1/6.2)。
- 大观察(反编译等)全文进 SQLite(§6.3),上下文只留结构化提取 + 摘要 + artifact#id(可 recall)。
- 每步重建 messages = [system] + [task+Working Memory(稳定前缀)] + [最近 window 步原始往返]。
  稳定前缀在前、易变在后,利于本地推理跨步复用 KV(§6.4)。
"""
from __future__ import annotations
import json


def _brief_args(args) -> str:
    if not args:
        return ""
    return ", ".join(f"{k}={str(v)[:24]}" for k, v in args.items())


class ContextManager:
    def __init__(self, store, run_id, window=6, big_threshold=800):
        self.store = store
        self.run_id = run_id
        self.window = window
        self.big_threshold = big_threshold
        self.goal = ""
        self.facts = []          # 已确认关键事实(字符串)
        self.step_notes = []     # 每步一行压缩摘要(供 Working Memory)
        self.exchanges = []      # [(assistant_text, observation_text)] 完整往返,只保留最近 window

    # —— 事实/目标 ——
    def set_goal(self, goal):
        self.goal = goal

    def add_fact(self, fact):
        if fact and fact not in self.facts:
            self.facts.append(fact)
            self.store.put_fact(self.run_id, "fact", fact)

    # —— 每步记录:压缩观察 + 存全量 + 更新 Working Memory ——
    def record(self, step, tool, args, obs) -> str:
        full = json.dumps(obs, ensure_ascii=False)
        brief = self._brief(tool, obs)
        # 总是存 artifact:既作工具缓存(避免重复 IDA 分析),又可 recall 重看全文
        art_id = self.store.put_artifact(self.run_id, tool, args, brief, full)
        ctx_view = self._context_view(tool, obs)
        if len(full) > self.big_threshold and isinstance(ctx_view, dict):
            ctx_view["_artifact_id"] = art_id
            ctx_view["_hint"] = f"全文已存 artifact#{art_id},需要重看用 recall"
        note = f"步{step}: {tool}({_brief_args(args)}) → {brief} [artifact#{art_id}]"
        self.step_notes.append(note)
        return f"OBSERVATION: {json.dumps(ctx_view, ensure_ascii=False)[:5000]}"

    def _brief(self, tool, obs) -> str:
        if not isinstance(obs, dict):
            return str(obs)[:120]
        if obs.get("error"):
            return f"错误: {str(obs['error'])[:100]}"
        if tool == "ida_decompile":
            pc = obs.get("pseudocode", "")
            first = pc.strip().splitlines()[0][:80] if pc else ""
            return f"反编译: {first}; callees={len(obs.get('callees',[]))} data_refs={len(obs.get('data_refs',[]))}"
        if tool == "ida_read_bytes":
            return f"{obs.get('size')}字节 @ {obs.get('addr')}: {obs.get('hex','')[:32]}…"
        if tool == "ida_list_functions":
            return f"{obs.get('count')} 个函数"
        if tool == "run_python":
            out = (obs.get("stdout") or "").strip().replace("\n", " ")
            return f"rc={obs.get('returncode')} stdout={out[:120]}" + (" [有stderr]" if obs.get("stderr") else "")
        if tool == "solve_locate":
            return f"find={obs.get('find')} avoid={obs.get('avoid')}"
        if tool == "solve_angr":
            return f"found={obs.get('found')} stdin={str(obs.get('stdin',''))[:40]}"
        if tool == "solve_verify":
            return f"accepted={obs.get('accepted')} ({obs.get('method')})"
        return json.dumps(obs, ensure_ascii=False)[:120]

    def _context_view(self, tool, obs) -> dict:
        """放进上下文的观察视图:保留结构化提取,长文本截断(全文在 SQLite)。"""
        if not isinstance(obs, dict):
            return {"result": str(obs)[:2000]}
        if tool == "ida_decompile":
            return {"pseudocode": obs.get("pseudocode", "")[:3500],
                    "callees": obs.get("callees", []), "data_refs": obs.get("data_refs", [])}
        if tool == "ida_list_functions":
            return {"count": obs.get("count"), "functions": obs.get("functions", [])[:120]}
        if tool == "run_python":
            return {"returncode": obs.get("returncode"),
                    "stdout": (obs.get("stdout") or "")[:3000],
                    "stderr": (obs.get("stderr") or "")[-800:], "timed_out": obs.get("timed_out")}
        return obs

    # —— Working Memory 渲染(§6.1) ——
    def working_memory_block(self) -> str:
        older = self.step_notes[:-self.window] if len(self.step_notes) > self.window else []
        lines = ["## 当前进度 (Working Memory)"]
        if self.goal:
            lines.append(f"- 目标: {self.goal}")
        if self.facts:
            lines.append("- 已确认事实: " + "; ".join(self.facts[-8:]))
        if older:
            lines.append("- 早前步骤(已压缩):")
            lines.extend("  " + n for n in older[-30:])
        return "\n".join(lines)

    # —— 每步重建 messages(稳定前缀在前) ——
    def build_messages(self, system_prompt, task):
        msgs = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": task + "\n\n" + self.working_memory_block()}]
        for a, o in self.exchanges[-self.window:]:
            msgs.append({"role": "assistant", "content": a})
            msgs.append({"role": "user", "content": o})
        return msgs

    def push_exchange(self, assistant_text, observation_text):
        self.exchanges.append((assistant_text, observation_text))
