"""Executor 上下文管理(§6):Working Memory + 结构化持久台账 + 历史窗口 + 外部记忆引用。

目标(§6 核心):让上下文**始终概括当前全部进度**,且远低于 64k。做法:
- **结构化台账(ledger)**:每次工具调用的关键结果按类型沉淀(函数地图/已读字节/解题尝试/概况),
  **永久常驻上下文**(不随窗口滑出),空间有界(每类去重+截断)。→ executor 牢记已知,不重复不空转。
- 只保留最近 window 步的**原始观察全文**(近处细节);更早步由台账代表(远处只留骨架)。
- 大观察(反编译等)全文进 SQLite(§6.3),上下文只留结构化提取 + artifact#id(可 recall)。
- 台账可从 store 跨轮重建(load_prior)→ 下一轮 executor / planner 继承前几轮的全部发现。
- 每步重建 messages = [system] + [task+台账(稳定前缀)] + [最近 window 步原始往返]。稳定前缀在前利于 KV 复用(§6.4)。
"""
from __future__ import annotations
import json
import re

# 折叠/分页/有界化已拆到 fold.py;此处再导出,保持既有导入路径可用
# (tests/test_fold_paginate.py 与 react_executor 的 recall 分支都从 context 导入)。
from antirev.memory.fold import (_ADDR_PREFIX, _clip_big, _fold_repeats,  # noqa: F401
                                 _norm_line, paginate, recall_view)
# 指纹/段图/签名渲染已拆到 render.py;同样再导出(tests/test_fingerprint.py 与
# tests/test_outline_render.py 都从 context 导入)。
from antirev.memory.render import (_addrs, _first_sig, _parse_addr,  # noqa: F401
                                   render_fingerprint, render_outline, render_todo)
# 台账(ACE 增量更新)已拆到 ledger.py。_FLAGISH_RE/_looks_secret 供本模块的 _harvest_facts 用。
from antirev.memory.ledger import Ledger, _FLAGISH_RE, _looks_secret  # noqa: F401

# 保留最近几次 run_python 的脚本全文。=1 时"上次错在哪、这次改了什么"的代码差就看不见了
# (P0-5/5985:步11 ValueError 与步12 半截 flag 之间无法对比 → 同错重试)。=2 够诊断又不占太多。
KEEP_PY_FULL = 2


def _brief_args(args, cap=100) -> str:
    if not args:
        return ""
    out = []
    for k, v in args.items():
        s = str(v)
        out.append(f"{k}={s[:cap]}…(+{len(s)-cap})" if len(s) > cap else f"{k}={v}")  # B2③:截长值(治 trace 内联 run_python 全脚本)
    return ", ".join(out)


class ContextManager:
    def __init__(self, store, run_id, window=6, big_threshold=800):
        self.store = store
        self.run_id = run_id
        self.window = window
        self.big_threshold = big_threshold
        self.goal = ""
        self.facts = []          # 已确认关键事实(字符串)
        self.user_hints = []     # 人工干预(human-in-the-loop):用户中途丢的提示,最高优先级
        self.step_notes = []     # 每步一行压缩摘要(调试/兜底用)
        self.exchanges = []      # [dict(thought,tool,args,obs,cid)] 原生 tool_calls 往返
        self._call_seq = 0       # 合成 tool_call_id 自增计数(回放需 assistant.tool_calls 与 role:tool 配对)
        self.ledger = Ledger()   # 结构化持久台账(ACE 增量更新,常驻上下文、空间有界)
        self._last_art_id = None  # 上一次 record 的 artifact id(供 push_exchange 关联,L1 靠它换引用)
        self._compact_n = 0      # L3 已压缩次数(达 MAX_L3_COMPACTS 转 planner)
        self.plan_steps = []     # 结构化 Plan 步骤(emit_plan 产物),供 TODO 复述

    # —— 台账字段代理:保持 ctx.func_map / ctx.attempts 等既有访问路径可用
    # (react_executor 的台账快照与 _break_hint、以及多处测试都直接读这些名字)——
    @property
    def func_map(self):
        return self.ledger.func_map

    @property
    def reads(self):
        return self.ledger.reads

    @property
    def attempts(self):
        return self.ledger.attempts

    @property
    def scans(self):
        return self.ledger.scans

    @property
    def func_outlines(self):
        return self.ledger.func_outlines

    @property
    def insights(self):
        return self.ledger.insights

    def ledger_block(self) -> str:
        return self.ledger.render()

    def _brief(self, tool, obs) -> str:
        return self.ledger.brief(tool, obs)

    # —— 事实/目标 ——
    def set_goal(self, goal):
        self.goal = goal

    def set_plan_steps(self, steps) -> None:
        """接收结构化 Plan 步骤(emit_plan 的 steps 字段),用于尾部 TODO 复述。"""
        self.plan_steps = list(steps or [])

    def _tools_used(self) -> set:
        """已实际调用过的工具名(据台账 + 往返;TODO 勾选判定用,纯规则、不花 LLM)。"""
        used = {a["tool"] for a in self.ledger.attempts if a.get("tool")}
        used |= {ex["tool"] for ex in self.exchanges if ex.get("tool")}
        # 台账的 scans/func_map/reads 也是"某工具跑过"的证据(attempts 只记解题类工具)
        for key, tool in (("analyze", "analyze"), ("functions", "ida_list_functions"),
                          ("key_functions", "find_key_functions"), ("floss", "floss")):
            if key in self.ledger.scans:
                used.add(tool)
        if self.ledger.func_map:
            used.add("ida_decompile")
        if self.ledger.reads:
            used.add("ida_read_bytes")
        return used

    def add_fact(self, fact):
        if fact and fact not in self.facts:
            self.facts.append(fact)
            self.store.put_fact(self.run_id, "fact", fact)

    def add_user_hint(self, hint):
        if hint and hint not in self.user_hints:
            self.user_hints.append(hint)

    # —— 每步记录:更新台账 + 压缩观察 + 存全量 ——
    def record(self, step, tool, args, obs, thought="") -> str:
        full = json.dumps(obs, ensure_ascii=False)
        brief = self._brief(tool, obs)
        # 总是存 artifact:既作工具缓存(避免重复 IDA 分析),又可 recall 重看全文、跨轮重建台账
        art_id = self.store.put_artifact(self.run_id, tool, args, brief, full)
        self.ledger.add(step, tool, args, obs)           # ← 关键:沉淀进结构化台账
        self._harvest(step, tool, args, obs, thought)    # B3/B4:强确认→facts,一般增量→insights
        ctx_view = self._context_view(tool, obs)
        if len(full) > self.big_threshold and isinstance(ctx_view, dict):
            ctx_view["_artifact_id"] = art_id
            ctx_view["_hint"] = f"全文已存 artifact#{art_id},需要重看用 recall"
        self._last_art_id = art_id      # 供 push_exchange 关联(L1 要靠它把旧全文换成 recall 引用)
        note = f"步{step}: {tool}({_brief_args(args)}) → {brief} [artifact#{art_id}]"
        self.step_notes.append(note)
        return f"OBSERVATION: {json.dumps(ctx_view, ensure_ascii=False)}"

    # —— B3/B4 信息萃取汇聚点:强确认→facts(跨轮落库),一般增量→insights(本轮持久)——
    def _harvest(self, step, tool, args, obs, thought):
        self._harvest_facts(step, tool, args, obs)           # 强确认 → facts(跨轮落库)
        self.ledger.add_insight(step, tool, obs, thought)    # 一般增量 → insights(本轮持久)

    def _harvest_facts(self, step, tool, args, obs):
        """B3:只收改变解题状态、跨轮仍成立的强确认(定位分支/求得输入/自验/密文密钥/flag候选)。"""
        if not isinstance(obs, dict) or obs.get("error"):
            return
        f = None
        if tool == "solve_locate" and obs.get("find"):
            f = f"成功分支已定位 find={obs.get('find')} avoid={obs.get('avoid')}"
        elif tool == "solve_angr" and obs.get("found"):
            f = f"angr 求得输入候选: {str(obs.get('stdin', ''))[:80]}"
        elif tool == "solve_verify" and obs.get("accepted"):
            f = f"候选已二进制自验通过({obs.get('method')}): {str(obs.get('candidate', ''))[:80]}"
        elif tool == "solve_stateless_transform" and obs.get("ok") and obs.get("verified"):
            f = f"一键变换求解并自验通过: {str(obs.get('flag', ''))[:80]}"
        elif tool == "ida_read_bytes" and _looks_secret(obs.get("hex", ""), obs.get("size") or 0):
            f = f"疑似密文/密钥 @ {obs.get('addr')} ({obs.get('size')}B): {(obs.get('hex') or '')[:64]}"
        elif tool == "run_python":
            m = _FLAGISH_RE.search(obs.get("stdout") or "")
            if m:
                f = f"run_python 产出 flag 候选: {m.group()}"
        if f:
            self.add_fact(f)     # 已有:去重 + store.put_fact 落库

    def _context_view(self, tool, obs) -> dict:
        """放进上下文的观察视图:完整保留工具结果全文(§不裁剪原则)——模型据全文决策,不再截断任何反编译/反汇编/输出。"""
        if not isinstance(obs, dict):
            return {"result": str(obs)}
        if tool in ("ida_decompile", "ida_disasm"):
            if obs.get("pseudocode"):
                return {"pseudocode": _clip_big(obs["pseudocode"]),
                        "callees": obs.get("callees", []), "data_refs": obs.get("data_refs", [])}
            return {"note": obs.get("note"), "disasm": _clip_big(obs.get("disasm") or ""),
                    "callees": obs.get("callees", [])}
        if tool == "ida_list_functions":
            fns = obs.get("functions", [])
            N = 80
            if len(fns) <= N:
                return {"count": obs.get("count"), "functions": fns}
            # B2①:大二进制别回全表(4052:2988函数=169k字符顶爆context)。优先列具名,截 top-N,全表可 recall
            junk = re.compile(r"^(sub_|nullsub_|unknown_|j_|loc_|def_|__|unk_)")
            named = [f for f in fns if not junk.match(f.get("name", ""))]
            shown = (named[:N] if len(named) >= N else (named + [f for f in fns if f not in named])[:N])
            return {"count": obs.get("count"), "functions": shown,
                    "_truncated": f"共{obs.get('count')}个函数,只列{len(shown)}(优先具名)。"
                                  f"缩小:ida_list_functions(filter=子串)/find_key_functions 打分/recall 取全表"}
        if tool == "find_key_functions":
            return {"count": obs.get("count"), "functions": obs.get("functions", [])}
        if tool == "run_python":
            return {"returncode": obs.get("returncode"),
                    "stdout": obs.get("stdout") or "",
                    "stderr": obs.get("stderr") or "", "timed_out": obs.get("timed_out")}
        return obs

    # —— 跨轮重建台账:从 store 读回本题此前所有工具调用,复用同一沉淀逻辑 ——
    def load_prior(self, store=None) -> int:
        store = store or self.store
        n = 0
        for a in store.list_artifacts(self.run_id):
            try:
                obs = json.loads(a["full_text"]) if a["full_text"] else {}
            except Exception:
                continue
            self.ledger.add(a["id"], a["tool"], a["args"], obs)
            n += 1
        for fr in store.get_facts(self.run_id):          # B3:重建强确认 facts(即便上轮 summary 空/崩,线索仍结转)
            v = fr.get("value") if isinstance(fr, dict) else str(fr)
            if v and v not in self.facts:
                self.facts.append(v)                      # append(不再 put_fact,免重复写库)
        return n

    def ledger_text(self) -> str:
        """供跨轮回传 planner。facts 置顶(planner 现在完全看不到 facts,此处补上)。"""
        parts = []
        if self.facts:
            parts.append("## 已确认关键事实(跨轮结转·最高可信,据此直接推进、别重复验证):")
            parts.extend(f"- {x}" for x in self.facts)
            parts.append("")
        parts.append(self.ledger_block())
        return "\n".join(parts)

    def decompile_dump(self, total_cap=40000) -> str:
        """本题所有反编译/反汇编的全文(同函数去重取最新),供 planner 重规划时通读、精选关键代码段。B2③:加全局上限防顶爆。"""
        seen = {}   # name_or_addr → (id, code);同函数多次反编译保留最新
        for a in self.store.list_artifacts(self.run_id):
            if a["tool"] not in ("ida_decompile", "ida_disasm"):
                continue
            try:
                obs = json.loads(a["full_text"]) if a["full_text"] else {}
            except Exception:
                continue
            code = obs.get("pseudocode") or obs.get("disasm") or ""
            if code:
                name = str((a["args"] or {}).get("name_or_addr", f"#{a['id']}"))
                seen[name] = (a["id"], code, obs)
        # 大函数(有 outline 且超 MAX):段图替代全文,治 planner 单次吞全文的 KV 崩服务(nodes.py:90);
        # 逐段下钻走 ida_disasm(段start,end=段end)。小函数走 _clip_big(折叠后全文,保真)。段头带 artifact#id 可 recall。
        MAX = 6000
        parts, used = [], 0
        for name, (aid, code, obs) in seen.items():
            outline = obs.get("outline")
            if outline and len(code) > MAX:
                body = (render_outline(outline)
                        + f"\n// 全文 artifact#{aid};逐段下钻 ida_disasm(段start, end=段end)")
            else:
                body = _clip_big(code, MAX)
            chunk = f"// ===== {name} (artifact#{aid}) =====\n{body}"
            if used + len(chunk) > total_cap:     # B2③:全局上限,防 planner 输入顶爆(4052)
                parts.append(f"// ...[已达 {total_cap} 字符上限,剩余 {len(seen)-len(parts)} 个函数未列全;planner 按需 recall 或让 executor 单独反编译]...")
                break
            parts.append(chunk)
            used += len(chunk)
        return "\n\n".join(parts)

    # —— 渐进式压缩入口(L1/L2;L3 见 compact_history)——
    def micro_compact(self, protect=None) -> int:
        """L1:把超出保护窗的旧工具结果换成 artifact 引用(零 LLM 成本、可 recall 取回)。"""
        from antirev.memory.compact import PROTECT_RECENT_STEPS, micro_compact
        return micro_compact(self.exchanges,
                             PROTECT_RECENT_STEPS if protect is None else protect)

    def drop_history(self, steps, reason="") -> dict:
        """L2:模型主动丢弃与当前任务无关的历史轮次(零 LLM 成本)。"""
        from antirev.memory.compact import PROTECT_RECENT_STEPS, drop_steps
        r = drop_steps(self.exchanges, steps, PROTECT_RECENT_STEPS)
        r["reason"] = reason
        return r

    def known_evidence(self) -> set:
        """台账里真实出现过的证据标识(地址 / artifact#N),供 L3 校验 confirmed[].evidence。

        这些是**工具真实产出**的,不是模型自述 —— 交叉校验的锚点。有了它,摘要里的
        地址/长度就不能凭记忆写(5985:同一段密文长度被五轮 summary 写成 32B→20B→25B)。
        """
        ev = set()
        for v in self.ledger.reads.values():
            if v.get("addr"):
                ev.add(str(v["addr"]))
        for key, v in self.ledger.func_map.items():
            ev.add(str(key))
            for r in (v.get("refs") or []):
                ev.add(str(r))
        for a in self.store.list_artifacts(self.run_id):
            ev.add(f"artifact#{a['id']}")
        return ev

    def compact_history(self, summary_text: str) -> None:
        """L3:把 append-only 历史整体替换为一条交接摘要。

        Codex 的形态要求:摘要必须落在历史**最末**(模型是按这个形态训练的)。且摘要
        **不孤军作战** —— 台账/facts/用户提示照旧由动态尾区承载,它们是工具产出的
        结构化真实证据,比 LLM 改写过的摘要可信。
        被替换掉的原始往返不丢:全文早已在 SQLite,可 recall 分页取回。
        """
        self._compact_n += 1
        self.exchanges = [{"thought": None, "tool": None, "args": {},
                           "obs": summary_text, "cid": None, "art_id": None,
                           "summary": True}]
        self._call_seq = 0

    # —— 动态尾区:唯一每步变化的段落 ——
    def dynamic_tail(self) -> str:
        """放在 messages 最末的动态区。顺序 = 优先级。

        为什么放最末(而非旧实现的 msg[1]):
        ① 缓存 —— mlx PromptTrie 只在"新 prompt 是旧 prompt 的扩展"时免 trim 复用;
           台账每步都变,放前缀等于让其后所有 KV 失效,放最末则只失效这一段。
        ② 注意力 —— 近因效应让尾部处于注意力峰值,台账/TODO 正需要被看见。
        两个目标在此**同向**,不是取舍。
        """
        lines = []
        if self.user_hints:     # 人工干预:置顶、最高优先级
            lines.append("## ⚠️⚠️ 用户实时提示(**最高优先级,立即照做,别再走老路/别再自我怀疑**):")
            lines.extend(f"  → {h}" for h in self.user_hints[-3:])
            lines.append("")
        lines.append("## 当前进度 (Working Memory)")
        if self.goal:
            lines.append(f"- 目标: {self.goal}")
        if self.facts:
            lines.append("- 已确认事实: " + "; ".join(self.facts[-8:]))
        lines.append(self.ledger_block())
        todo = render_todo(self.plan_steps, self._tools_used())
        if todo:
            lines.append("")
            lines.append(todo)      # 最末:近因效应峰值(Manus 注意力锚定)
        return "\n".join(lines)

    # —— 供 planner 侧(ledger_text)与既有调用点复用 ——
    def working_memory_block(self) -> str:
        return self.dynamic_tail()

    # —— 每步重建 messages(cache 友好布局)——
    def build_messages(self, system_prompt, task):
        """布局:[静态 system] + [半静态 task/Plan] + [append-only 工具往返] + [动态尾区]。

        历史**不再滑窗**:append-only 让本次 prompt 恰为上次 prompt 的扩展,命中 mlx
        PromptTrie 的 `shorter` 路径(只 prefill 增量、免 trim)。上下文规模由 L1/L3 压缩层
        承接,不靠丢弃最近步骤。

        本方法现在是**纯函数**:不再在渲染时改写任何 exchange(run_python 占位符已在
        push_exchange 时冻结),所以同样的 exchanges 永远渲染出同样的字节。
        """
        msgs = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": task}]
        for ex in self.exchanges:
            thought, tool, args = ex["thought"], ex["tool"], ex["args"]
            obs, cid = ex["obs"], ex.get("cid")
            if ex.get("summary"):       # L3 交接摘要:单独一条 user,且始终在历史最末
                msgs.append({"role": "user", "content": obs})
                continue
            if tool is None:
                # 无 tool_call(格式纠错/被拒 flag):assistant 正文 + user 追问
                msgs.append({"role": "assistant", "content": thought or "(无输出)"})
                msgs.append({"role": "user", "content": obs})
                continue
            asst = {"role": "assistant",
                    "tool_calls": [{"id": cid, "type": "function",
                                    "function": {"name": tool,
                                                 "arguments": json.dumps(args, ensure_ascii=False)}}]}
            if thought:
                asst["content"] = thought
            msgs.append(asst)
            msgs.append({"role": "tool", "tool_call_id": cid, "content": obs})
        msgs.append({"role": "user", "content": self.dynamic_tail()})
        return msgs

    def push_exchange(self, thought, tool=None, args=None, observation_text=""):
        """记录一步原生往返。tool=None 表示模型没调工具(格式纠错/被拒 flag),observation_text 作为 user 追问回灌;
        否则合成 tool_call_id,回放时发 assistant.tool_calls + role:tool。"""
        cid = None
        if tool is not None:
            self._call_seq += 1
            cid = f"call_{self._call_seq}"
        args = dict(args) if isinstance(args, dict) else {}
        self.exchanges.append({"thought": thought, "tool": tool, "args": args,
                               "obs": observation_text, "cid": cid,
                               "art_id": self._last_art_id})
        self._last_art_id = None        # 用掉即清,避免误关联到下一步
        if tool == "run_python" and args.get("code"):
            self._freeze_prior_py()     # 决策冻结:新脚本入队后,把过老的脚本一次性定型

    def _freeze_prior_py(self) -> None:
        """把除最近 KEEP_PY_FULL 次之外的 run_python code 换成占位符,**且只换一次、此后不再动**。

        两个目的:
        ① 缓存 —— 写回 exchanges 后 build_messages 成为纯函数,不再每步按"当前最后一个 py"
           动态重算。改动次数从 O(步数) 降到 O(run_python 次数)。
        ② 可诊断(P0-5)—— 保留最近 **2** 次而非 1 次全文,模型能对比"上次错在哪、这次改了什么"。
           只留 1 次时,步11 的 ValueError 与步12 的半截 flag 之间的代码差就看不见了(5985 教训)。
        """
        py_idx = [i for i, ex in enumerate(self.exchanges)
                  if ex["tool"] == "run_python" and (ex["args"] or {}).get("code")]
        for i in py_idx[:-KEEP_PY_FULL] if KEEP_PY_FULL else py_idx:
            ex = self.exchanges[i]
            code = ex["args"]["code"]
            if code.startswith("<此前脚本已省略"):
                continue                # 已冻结 → 幂等,不重写(重写会打破字节稳定)
            ex["args"] = dict(ex["args"])
            ex["args"]["code"] = (f"<此前脚本已省略({len(code)}字符);只保留最近 {KEEP_PY_FULL} 次 "
                                  f"run_python 全文,更早的尝试看其 OBSERVATION 输出>")
