"""结构化台账(ACE 式增量更新):把每次工具调用的关键结果按类型沉淀,常驻上下文、空间有界。

为什么是增量而非重写:ACE 论文指出"让 LLM 整体重写不断变长的上下文"会触发**上下文崩溃**
(突然输出极短摘要,累积知识瞬间丢失)与**简洁偏向**(丢弃只在特定场景有用的启发式/技巧/坑)。
台账走纯规则的增删改:每类按 key 去重、追加,旧信息 100% 保留 —— 天然规避这两个失效模式。
这也是它能扮演"结构化真实证据"角色的原因:内容来自工具输出,不经 LLM 改写。

有界化(治 P1-1:5985 实测 attempts 膨胀到 47 条 ~5.4k 字符常驻,有效信号被淹没):
每类都有上限,超限丢最旧(insights/attempts)或丢最早插入的键(func_map/reads)。
本类**不碰 store** —— 落库(facts/artifact)由 ContextManager 负责,便于独立构造与测试。
"""
from __future__ import annotations
import json
import re

from antirev.memory.render import (_addrs, _first_sig, _parse_addr,
                                   render_fingerprint, render_outline)

_FLAGISH_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}]{2,}\}")
_HEXCONST_RE = re.compile(r"\b0x[0-9a-fA-F]{2,}\b")
_ESS_KW = re.compile(
    r"(算法|密钥|密文|明文|偏移|delta|轮数|rounds?|s-?盒|码表|异或|xor|加密|解密|补码|大小端|字节序|"
    r"输入长度|长度\s*[:：]?\s*\d|flag\s*格式|memcmp|strcmp|入口|entry|"
    r"是\s*(?:标准|魔改)?\s*(tea|xtea|xxtea|rc4|aes|base64|md5|sha))", re.I)
_SECRET_SZ = {8, 16, 24, 32, 40, 48, 56, 64}

# —— 各类台账容量上限(P1-1:此前 docs/context.md 写 50/20 但代码里根本没有截断)——
MAX_FUNC_MAP = 50
MAX_READS = 40
MAX_ATTEMPTS = 20
MAX_INSIGHTS = 40


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


def _cap_dict(d: dict, limit: int) -> None:
    """就地把 dict 截到 limit 条:丢最早插入的键(Python 3.7+ dict 保序)。"""
    while len(d) > limit:
        d.pop(next(iter(d)))


class Ledger:
    """台账状态 + 沉淀 + 渲染。无 store 依赖,可独立构造与测试。"""

    def __init__(self):
        self.func_map = {}       # key(name_or_addr) → {sig, fp, calls[], refs[], step}
        self.reads = {}          # key(addr:size) → {addr, size, head, step}
        self.attempts = []       # 时序: {step, tool, digest}
        self.scans = {}          # 概况(最新覆盖): analyze/functions/key_functions/floss → 一行
        self.func_outlines = {}  # key → {outline, seen:set(已下钻 seg_id)}
        self.insights = []       # 每步信息精华: {step, text}

    # —— 沉淀:把一次工具调用的关键结果按类型入账(去重 + 有界)——
    def add(self, step, tool, args, obs) -> None:
        if not isinstance(obs, dict):
            if tool in ("run_python", "terminal"):
                self._add_attempt(step, tool, str(obs))
            return
        if obs.get("error"):
            # 失败也要记(Manus:保留错误痕迹能降低重犯;避免重复踩同一坑)
            self._add_attempt(step, tool, f"错误 {str(obs['error'])}")
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
            self.func_map[key] = {"sig": sig, "fp": render_fingerprint(feat) if feat else "",
                                  "calls": _addrs(obs.get("callees")),
                                  "refs": _addrs(obs.get("data_refs")), "step": step}
            _cap_dict(self.func_map, MAX_FUNC_MAP)
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
            self.reads[f"{disp}:{obs.get('size')}"] = {
                "addr": disp, "size": obs.get("size"), "head": obs.get("hex") or "", "step": step}
            _cap_dict(self.reads, MAX_READS)
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
            self.scans["key_functions"] = "关键函数排序 → " + "; ".join(
                f"{f.get('addr')}(score{f.get('score')}:{','.join(f.get('why', []))})" for f in fns)
        elif tool == "floss":
            self.scans["floss"] = f"字符串: {(obs.get('output') or '').replace(chr(10), ' ')[:160]}"
        elif tool in ("run_python", "solve_angr", "solve_verify", "solve_locate", "unicorn_emulate"):
            self._add_attempt(step, tool, self.brief(tool, obs))

    def _add_attempt(self, step, tool, digest) -> None:
        self.attempts.append({"step": step, "tool": tool, "digest": digest})
        if len(self.attempts) > MAX_ATTEMPTS:
            self.attempts = self.attempts[-MAX_ATTEMPTS:]

    def add_insight(self, step, tool, obs, thought) -> None:
        """B4:抽'一般增量'——thought 新结论 + run_python 非 flag 中间值(flag 归 facts)。"""
        bits = []
        th = _essence_from_thought(thought)
        if th:
            bits.append(th)
        if tool == "run_python" and isinstance(obs, dict) and not obs.get("error"):
            out = (obs.get("stdout") or "").strip()
            if out and not _FLAGISH_RE.search(out):
                first = next((ln for ln in out.splitlines() if ln.strip()), "")
                if first:
                    bits.append("py→" + first[:80])
        text = "; ".join(bits)[:160]
        if not text or any(it["text"] == text for it in self.insights[-6:]):
            return
        self.insights.append({"step": step, "text": text})
        if len(self.insights) > MAX_INSIGHTS:
            self.insights = self.insights[-MAX_INSIGHTS:]

    # —— 一行摘要(给 step_notes / attempts digest / artifact summary)——
    def brief(self, tool, obs) -> str:
        if not isinstance(obs, dict):
            return str(obs)
        if obs.get("error"):
            return f"错误: {str(obs['error'])}"
        if tool in ("ida_decompile", "ida_disasm"):
            if obs.get("pseudocode"):
                return (f"反编译: {_first_sig(obs['pseudocode'])}; "
                        f"callees={len(obs.get('callees', []))} data_refs={len(obs.get('data_refs', []))}")
            if obs.get("disasm"):
                return (f"反汇编({(obs.get('disasm') or '').count(chr(10)) + 1}行); "
                        f"callees={len(obs.get('callees', []))}")
            return "无输出"
        if tool == "ida_read_bytes":
            return f"{obs.get('size')}字节 @ {obs.get('addr')}: {obs.get('hex', '')}"
        if tool == "ida_list_functions":
            return f"{obs.get('count')} 个函数"
        if tool == "find_key_functions":
            fns = obs.get("functions", [])
            return f"{len(fns)}候选,top: " + ", ".join(
                f"{f.get('addr')}(score{f.get('score')})" for f in fns)
        if tool == "run_python":
            out = (obs.get("stdout") or "").strip().replace("\n", " ")
            return f"rc={obs.get('returncode')} stdout={out}" + (" [有stderr]" if obs.get("stderr") else "")
        if tool == "solve_locate":
            return f"find={obs.get('find')} avoid={obs.get('avoid')}"
        if tool == "solve_angr":
            return f"found={obs.get('found')} stdin={str(obs.get('stdin', ''))}"
        if tool == "solve_verify":
            return f"accepted={obs.get('accepted')} ({obs.get('method')})"
        return json.dumps(obs, ensure_ascii=False)

    # —— 渲染(常驻上下文;每类去重+截断,空间有界)——
    def render(self) -> str:
        """分区顺序 = **从最稳定到最易变**,这是刻意的。

        台账整体落在动态尾区,但它内部同样存在前缀:越靠前的分区越稳定,
        前缀就越长、KV 复用越多。实测(未排序前)尾区自身命中率只有 27% 且随步数递减
        (41%→18%),罪魁是"已反编译函数(**N个**...)"这种**行内计数** —— 每加一个函数,
        计数一变,从那个字符起整个尾区全废。

        所以:①纯追加的分区(func_map/reads)排前 ②覆盖更新的(scans/outlines)居中
        ③滑动窗口的(attempts/insights)排最后 ④**任何计数一律移到该分区末尾**,
        不放在分区首行。
        """
        lines = ["## 已知台账(所有工具调用结果的持久记录 —— 查过的别重复查,据此决定下一步)"]
        # ① 纯追加区(新条目只在末尾长出来 → 前缀最稳)
        if self.func_map:
            lines.append("- 已反编译函数(addr → 签名 | 算法指纹 | calls | refs):")
            for key, v in self.func_map.items():
                calls = ",".join(v["calls"]) if v["calls"] else "-"
                refs = ",".join(v["refs"]) if v["refs"] else "-"
                lines.append(f"   {key} {v['sig']} | {v.get('fp') or '-'} | calls {calls} | refs {refs}")
            lines.append(f"   (共 {len(self.func_map)} 个)")      # 计数放末尾,不污染前缀
        if self.reads:
            lines.append("- 已读字节:")
            for v in self.reads.values():
                lines.append(f"   {v['addr']} ({v['size']}B) {v['head']}")
        # ② 覆盖更新区(值会原地改,但键集合增长慢)
        if self.func_outlines:
            lines.append("- 大函数分段导航(★核心段;下钻 ida_disasm(段start, end=段end);逐段理解防遗漏):")
            for e in self.func_outlines.values():
                lines.append("  " + render_outline(e["outline"], e["seen"]).replace("\n", "\n  "))
        if self.scans:
            for k in ("analyze", "unpack", "functions", "key_functions", "floss"):
                if k in self.scans:
                    lines.append(f"- {k}: {self.scans[k]}")
        # ③ 滑动窗口区(会丢最旧 → 整段重排,放最后把影响限制在尾巴上)
        if self.attempts:
            lines.append("- 解题尝试(时序):")
            for a in self.attempts:
                lines.append(f"   步{a['step']} {a['tool']} → {a['digest']}")
        if self.insights:     # B4:每步信息精华,窗口滑出后仍留,防重复推导
            lines.append("- 每步关键增量(推理结论/中间值,窗口外仍留;别重复推导):")
            for it in self.insights[-20:]:
                lines.append(f"   步{it['step']}: {it['text']}")
        return "\n".join(lines)
