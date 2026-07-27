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
                                   render_fingerprint, render_outline)


def _brief_args(args, cap=100) -> str:
    if not args:
        return ""
    out = []
    for k, v in args.items():
        s = str(v)
        out.append(f"{k}={s[:cap]}…(+{len(s)-cap})" if len(s) > cap else f"{k}={v}")  # B2③:截长值(治 trace 内联 run_python 全脚本)
    return ", ".join(out)


# —— B3/B4:突破点(facts)与每步信息精华(insights)的抽取辅助 ——
_FLAGISH_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}]{2,}\}")
_HEXCONST_RE = re.compile(r"\b0x[0-9a-fA-F]{2,}\b")
_ESS_KW = re.compile(
    r"(算法|密钥|密文|明文|偏移|delta|轮数|rounds?|s-?盒|码表|异或|xor|加密|解密|补码|大小端|字节序|"
    r"输入长度|长度\s*[:：]?\s*\d|flag\s*格式|memcmp|strcmp|入口|entry|"
    r"是\s*(?:标准|魔改)?\s*(tea|xtea|xxtea|rc4|aes|base64|md5|sha))", re.I)
_SECRET_SZ = {8, 16, 24, 32, 40, 48, 56, 64}


def _looks_secret(hexstr, size) -> bool:
    """B3:疑似密文/密钥判据(纯离线)——非空、非全零、字节多样,或落常见密码块长。"""
    if not hexstr or not size or size < 8:
        return False
    try:
        b = bytes.fromhex(hexstr) if len(hexstr) % 2 == 0 else b""
    except ValueError:
        return False
    if not b or set(b) == {0}:
        return False
    return size in _SECRET_SZ or len(set(b)) / len(b) >= 0.4


def _essence_from_thought(thought: str) -> str:
    """B4:从 thought 抽'新确认结论'一句(优先含关键词且带 hex/数值的句子,截 100)。"""
    if not thought:
        return ""
    sents = re.split(r"[。\n;；.]", thought)
    for s in sents:
        s = s.strip()
        if len(s) >= 4 and _ESS_KW.search(s) and (_HEXCONST_RE.search(s) or re.search(r"\d", s)):
            return s[:100]
    for s in sents:
        s = s.strip()
        if len(s) >= 6 and _ESS_KW.search(s):
            return s[:100]
    return ""


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
        self.exchanges = []      # [dict(thought,tool,args,obs,cid)] 原生 tool_calls 往返,只保留最近 window
        self._call_seq = 0       # 合成 tool_call_id 自增计数(回放需 assistant.tool_calls 与 role:tool 配对)
        # —— 结构化持久台账(§6:常驻上下文,空间有界)——
        self.func_map = {}       # 反编译函数地图: key(name_or_addr) → {sig, calls[], refs[], step}
        self.reads = {}          # 已读字节: key(addr:size) → {addr, size, head, step}
        self.attempts = []       # 解题尝试(时序): {step, tool, digest}
        self.scans = {}          # 概况(最新覆盖): analyze/list_functions/floss/unpack → 一行摘要
        self.func_outlines = {}  # 大函数分段地图: key(name_or_addr) → {outline, seen:set(已下钻 seg_id)}
        self.insights = []       # B4:每步信息精华(推理结论/中间值),窗口外持久、本轮有界 40

    # —— 事实/目标 ——
    def set_goal(self, goal):
        self.goal = goal

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
        self._ledger_add(step, tool, args, obs)          # ← 关键:沉淀进结构化台账
        self._harvest(step, tool, args, obs, thought)    # B3/B4:强确认→facts,一般增量→insights
        ctx_view = self._context_view(tool, obs)
        if len(full) > self.big_threshold and isinstance(ctx_view, dict):
            ctx_view["_artifact_id"] = art_id
            ctx_view["_hint"] = f"全文已存 artifact#{art_id},需要重看用 recall"
        note = f"步{step}: {tool}({_brief_args(args)}) → {brief} [artifact#{art_id}]"
        self.step_notes.append(note)
        return f"OBSERVATION: {json.dumps(ctx_view, ensure_ascii=False)}"

    # —— B3/B4 信息萃取汇聚点:强确认→facts(跨轮落库),一般增量→insights(本轮持久)——
    def _harvest(self, step, tool, args, obs, thought):
        self._harvest_facts(step, tool, args, obs)
        self.add_insight(step, tool, args, obs, thought)

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

    def add_insight(self, step, tool, args, obs, thought):
        """B4:抽'一般增量'——thought 新结论 + run_python 非flag中间值(flag 归 facts)。"""
        bits = []
        th = _essence_from_thought(thought)
        if th:
            bits.append(th)
        if tool == "run_python" and isinstance(obs, dict) and not obs.get("error"):
            out = (obs.get("stdout") or "").strip()
            if out and not _FLAGISH_RE.search(out):
                first = next((l for l in out.splitlines() if l.strip()), "")
                if first:
                    bits.append("py→" + first[:80])
        text = "; ".join(bits)[:160]
        if not text or any(it["text"] == text for it in self.insights[-6:]):
            return
        self.insights.append({"step": step, "text": text})
        if len(self.insights) > 40:
            self.insights = self.insights[-40:]

    # —— 结构化台账:把一次工具调用的关键结果按类型沉淀(去重)——
    def _ledger_add(self, step, tool, args, obs):
        if not isinstance(obs, dict):
            if tool in ("run_python", "terminal"):
                self.attempts.append({"step": step, "tool": tool, "digest": str(obs)})
            return
        if obs.get("error"):
            # 失败也要记(避免重复踩同一坑),归到尝试/概况
            self.attempts.append({"step": step, "tool": tool, "digest": f"错误 {str(obs['error'])}"})
            return
        if tool in ("ida_decompile", "ida_disasm"):
            key = str(args.get("name_or_addr", f"#{step}")).lower()
            pc = obs.get("pseudocode")
            if pc:
                sig = _first_sig(pc)
            elif obs.get("disasm"):     # 反汇编兜底(hexrays失败或直接disasm)
                first = obs["disasm"].splitlines()[0] if obs["disasm"] else ""
                sig = "[反汇编] " + first[:60]
            else:
                sig = ""
            feat = obs.get("fingerprint_feat")
            fp = render_fingerprint(feat) if feat else ""
            self.func_map[key] = {"sig": sig, "fp": fp, "calls": _addrs(obs.get("callees")),
                                  "refs": _addrs(obs.get("data_refs")), "step": step}
            outline = obs.get("outline")
            if outline:     # 大函数分段地图入台账(常驻;record 已把 obs 存 artifact → 跨轮 load_prior 免费重建)
                self.func_outlines.setdefault(key, {"outline": None, "seen": set()})["outline"] = outline
            if tool == "ida_disasm":     # 局部下钻 → 命中段标已看(覆盖追踪)
                addr = _parse_addr(args.get("name_or_addr"))
                if addr is not None:
                    for e in self.func_outlines.values():
                        for seg in (e["outline"] or {}).get("segments", []):
                            if int(seg["start"], 16) <= addr < int(seg["end"], 16):
                                e["seen"].add(seg["id"])
        elif tool == "ida_read_bytes":
            disp = str(args.get("name_or_addr", obs.get("addr")))
            key = f"{disp}:{obs.get('size')}"
            self.reads[key] = {"addr": disp, "size": obs.get("size"),
                               "head": obs.get("hex") or "", "step": step}
        elif tool == "analyze":
            fi = obs.get("file_info", {}) or {}
            pk = obs.get("packer", {}) or {}
            self.scans["analyze"] = (f"{fi.get('format')} {fi.get('arch')} {fi.get('bits')}bit "
                                     f"imports={fi.get('num_imports')} size={fi.get('size')} "
                                     f"packed={pk.get('packed_likely')}")
        elif tool == "ida_list_functions":
            self.scans["functions"] = f"{obs.get('count')} 个函数(filter={args.get('filter','')!r})"
        elif tool == "find_key_functions":
            fns = obs.get("functions", [])
            top = "; ".join(f"{f.get('addr')}(score{f.get('score')}:{','.join(f.get('why', []))})"
                            for f in fns)
            self.scans["key_functions"] = f"关键函数排序 → {top}"
        elif tool == "floss":
            out = (obs.get("output") or "").replace("\n", " ")
            self.scans["floss"] = f"字符串: {out[:160]}"
        elif tool in ("run_python", "solve_angr", "solve_verify", "solve_locate", "unicorn_emulate"):
            self.attempts.append({"step": step, "tool": tool, "digest": self._brief(tool, obs)})

    def _brief(self, tool, obs) -> str:
        if not isinstance(obs, dict):
            return str(obs)
        if obs.get("error"):
            return f"错误: {str(obs['error'])}"
        if tool in ("ida_decompile", "ida_disasm"):
            if obs.get("pseudocode"):
                return f"反编译: {_first_sig(obs['pseudocode'])}; callees={len(obs.get('callees',[]))} data_refs={len(obs.get('data_refs',[]))}"
            if obs.get("disasm"):
                return f"反汇编({(obs.get('disasm') or '').count(chr(10))+1}行); callees={len(obs.get('callees',[]))}"
            return "无输出"
        if tool == "ida_read_bytes":
            return f"{obs.get('size')}字节 @ {obs.get('addr')}: {obs.get('hex','')}"
        if tool == "ida_list_functions":
            return f"{obs.get('count')} 个函数"
        if tool == "find_key_functions":
            fns = obs.get("functions", [])
            return f"{len(fns)}候选,top: " + ", ".join(f"{f.get('addr')}(score{f.get('score')})" for f in fns)
        if tool == "run_python":
            out = (obs.get("stdout") or "").strip().replace("\n", " ")
            return f"rc={obs.get('returncode')} stdout={out}" + (" [有stderr]" if obs.get("stderr") else "")
        if tool == "solve_locate":
            return f"find={obs.get('find')} avoid={obs.get('avoid')}"
        if tool == "solve_angr":
            return f"found={obs.get('found')} stdin={str(obs.get('stdin',''))}"
        if tool == "solve_verify":
            return f"accepted={obs.get('accepted')} ({obs.get('method')})"
        return json.dumps(obs, ensure_ascii=False)

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
            self._ledger_add(a["id"], a["tool"], a["args"], obs)
            n += 1
        for fr in store.get_facts(self.run_id):          # B3:重建强确认 facts(即便上轮 summary 空/崩,线索仍结转)
            v = fr.get("value") if isinstance(fr, dict) else str(fr)
            if v and v not in self.facts:
                self.facts.append(v)                      # append(不再 put_fact,免重复写库)
        return n

    # —— 台账渲染(常驻上下文;每类去重+截断,空间有界)——
    def ledger_block(self) -> str:
        lines = ["## 已知台账(所有工具调用结果的持久记录 —— 查过的别重复查,据此决定下一步)"]
        if self.scans:
            for k in ("analyze", "unpack", "functions", "key_functions", "floss"):
                if k in self.scans:
                    lines.append(f"- {k}: {self.scans[k]}")
        if self.func_map:
            lines.append(f"- 已反编译函数({len(self.func_map)}个, addr → 签名 | 算法指纹 | calls | refs):")
            for key, v in self.func_map.items():
                calls = ",".join(v["calls"]) if v["calls"] else "-"
                refs = ",".join(v["refs"]) if v["refs"] else "-"
                fp = v.get("fp") or "-"
                lines.append(f"   {key} {v['sig']} | {fp} | calls {calls} | refs {refs}")
        if self.func_outlines:
            lines.append("- 大函数分段导航(★核心段;下钻 ida_disasm(段start, end=段end);逐段理解防遗漏):")
            for e in self.func_outlines.values():
                lines.append("  " + render_outline(e["outline"], e["seen"]).replace("\n", "\n  "))
        if self.reads:
            lines.append("- 已读字节:")
            for v in self.reads.values():
                lines.append(f"   {v['addr']} ({v['size']}B) {v['head']}")
        if self.attempts:
            lines.append("- 解题尝试(时序):")
            for a in self.attempts:
                lines.append(f"   步{a['step']} {a['tool']} → {a['digest']}")
        if self.insights:     # B4:每步信息精华,窗口滑出后仍留,防重复推导
            lines.append("- 每步关键增量(推理结论/中间值,窗口外仍留;别重复推导):")
            for it in self.insights[-20:]:
                lines.append(f"   步{it['step']}: {it['text']}")
        return "\n".join(lines)

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

    # —— Working Memory 渲染(§6.1):目标 + 事实 + 结构化台账 ——
    def working_memory_block(self) -> str:
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
        return "\n".join(lines)

    # —— 每步重建 messages(稳定前缀在前) ——
    def build_messages(self, system_prompt, task):
        msgs = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": task + "\n\n" + self.working_memory_block()}]
        win = self.exchanges[-self.window:]
        # run_python 脚本只保留最近一次的全文;更早的换占位(反编译等其它工具结果一律全量保留)
        last_py = max((i for i, ex in enumerate(win) if ex.get("tool") == "run_python"), default=-1)
        for i, ex in enumerate(win):
            thought, tool, args, obs, cid = ex["thought"], ex["tool"], ex["args"], ex["obs"], ex.get("cid")
            if tool is None:
                # 无 tool_call(格式纠错/被拒 flag):assistant 正文 + user 追问
                msgs.append({"role": "assistant", "content": thought or "(无输出)"})
                msgs.append({"role": "user", "content": obs})
                continue
            if tool == "run_python" and i != last_py and isinstance(args, dict) and args.get("code"):
                args = dict(args)
                n = len(args["code"])
                args["code"] = f"<此前脚本已省略({n}字符);只保留最近一次 run_python 全文,历史尝试看其 OBSERVATION 输出>"
            asst = {"role": "assistant",
                    "tool_calls": [{"id": cid, "type": "function",
                                    "function": {"name": tool,
                                                 "arguments": json.dumps(args, ensure_ascii=False)}}]}
            if thought:
                asst["content"] = thought
            msgs.append(asst)
            msgs.append({"role": "tool", "tool_call_id": cid, "content": obs})
        return msgs

    def push_exchange(self, thought, tool=None, args=None, observation_text=""):
        """记录一步原生往返。tool=None 表示模型没调工具(格式纠错/被拒 flag),observation_text 作为 user 追问回灌;
        否则合成 tool_call_id,回放时发 assistant.tool_calls + role:tool。"""
        cid = None
        if tool is not None:
            self._call_seq += 1
            cid = f"call_{self._call_seq}"
        self.exchanges.append({"thought": thought, "tool": tool,
                               "args": args if isinstance(args, dict) else {},
                               "obs": observation_text, "cid": cid})
