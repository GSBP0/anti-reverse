"""planner/summary 结构化输出 schema(原生 tool_calls 风格)+ 校验 + 渲染。

背景:此前 planner 产 Plan、executor 产进展总结都走**自由文本**(nodes.py:116 / react_executor.py:_summarize_round),
模型爱漏字段(忘写 flag 格式/忘列卡点),更爱**幻觉工具**(建议 x64dbg/GDB 这类离线不存在的工具,executor 白跑一轮)。
本模块给两处各一份 OpenAI function schema,逼模型按字段填,再配校验+渲染:
- report_progress(REPORT_PROGRESS):executor 每轮结束的结构化进展总结 → validate_report 兜漏(算法/卡点/下一步必填)
  → render_report 转回高密度中文,注入下一轮 planner(替代 _summarize_round 的 ①②③④ 自由文本)。
- emit_plan(EMIT_PLAN):planner 的结构化 Plan → validate_plan **杀幻觉工具**(每步 tool 必须 ∈ 真实工具集)
  → render_plan 转成 executor 消费的 Plan 文本(题型/架构/关键代码/分步含工具+成功判据/flag格式)。

纯函数、无外部依赖:tool_names 由调用方传入(不 import registry,避免耦合;真实集合是 registry.TOOL_NAMES)。
"""
from __future__ import annotations
import json


# —— OpenAI function schema 构造(与 registry._fn 同构,便于直接进 tools=[...])——
def _fn(name, description, properties, required):
    return {"type": "function", "function": {
        "name": name,
        "description": description,
        "parameters": {"type": "object", "properties": properties, "required": required},
    }}


_STR = {"type": "string"}
_STRARR = {"type": "array", "items": {"type": "string"}}


def _objarr(props, description=""):
    """数组-of-对象的属性 schema(items 带固定字段);description 可选。"""
    d = {"type": "array", "items": {"type": "object", "properties": props}}
    if description:
        d["description"] = description
    return d


# —— executor 进展总结:对应 _summarize_round 的 ①算法 ②关键数据 ③试过 ④卡点/下一步 ——
REPORT_PROGRESS = _fn(
    "report_progress",
    "本轮到此结束、未解出时写结构化进展总结,传给下一轮规划者。逐项如实填、别客套,漏项会被打回。",
    {
        "confirmed_algo": {**_STR, "description":
                           "已确认的算法/校验逻辑:输入如何被处理/变换、和什么比较、密钥或常量是什么"},
        "key_data": _objarr(
            {"addr": {**_STR, "description": "真实地址 0x..(按 data_refs,别用伪代码显示名)"},
             "value": {**_STR, "description": "内容(hex 或明文)"},
             "meaning": {**_STR, "description": "这是什么:密文/密钥/目标值/输入长度…"}},
            "已取到的关键数据(密文/密钥/目标值的真实地址+内容);没取到可空"),
        "tried": _objarr(
            {"approach": {**_STR, "description": "试过的解法(工具+思路)"},
             "why_failed": {**_STR, "description": "为何失败(乱码/超时/地址错…)"}},
            "试过哪些解法、分别为何失败;首轮可空"),
        "blocker": {**_STR, "description": "现在具体卡在哪(一句话点明症结)"},
        "next_steps": {**_STRARR, "description": "下一轮应换的不同思路(分步,别重复失败路径)"},
    },
    ["confirmed_algo", "key_data", "tried", "blocker", "next_steps"],
)


# —— planner 结构化 Plan:对应 nodes.py 里"主类型/架构/关键线索/分步/flag格式/关键代码段" ——
EMIT_PLAN = _fn(
    "emit_plan",
    "产出结构化解题 Plan,供 executor 逐步执行。每步的 tool **只能从真实可用工具里选**(严禁 x64dbg/GDB 等离线不存在的)。",
    {
        "problem_type": {**_STR, "description":
                         "主题型:flag校验/加密(异或/TEA/XTEA/XXTEA/RC4/AES/base64/移位)/VM混淆/加壳/反调试/运行时解密"},
        "arch": {**_STR, "description": "架构/位数/格式,如 x86-64 ELF"},
        "key_findings": {**_STRARR, "description": "关键线索/已确认事实(壳、提示串、目标分支…)"},
        "key_code": _objarr(
            {"func": {**_STR, "description": "函数名"},
             "addr": {**_STR, "description": "地址 0x.."},
             "note": {**_STR, "description": "这段代码的作用/核心运算(逐字节 xor、TEA 轮…)"}},
            "从反编译精选的关键代码段(只留解题核心逻辑,供 executor 直接据此动手、不必重反编译)"),
        "steps": _objarr(
            {"goal": {**_STR, "description": "该步目标"},
             "tool": {**_STR, "description": "只从真实工具里选的工具名"},
             "success_criteria": {**_STR, "description": "成功判据(拿到什么算这步成)"}},
            "分步:每步 目标+工具+成功判据,务实可执行"),
        "flag_format": {**_STR, "description": "flag 格式(提示非铁律):以二进制里实际比较/输出的串为准;NSSCTF 常收录原题,前缀可能是 LitCTF/HDCTF/HZCTF/flag 等,别因非 NSSCTF{} 就否定正确解"},
    },
    ["problem_type", "steps"],
)


# —— 校验(返回缺失/非法字段名列表,空列表=通过)——
def validate_report(d: dict) -> list:
    """兜漏进展总结:confirmed_algo/blocker 必须非空、next_steps 必须至少一条;key_data/tried 允许空。"""
    d = d or {}
    missing = []
    for f in ("confirmed_algo", "blocker"):
        if not str(d.get(f) or "").strip():
            missing.append(f)
    if not [s for s in (d.get("next_steps") or []) if str(s).strip()]:
        missing.append("next_steps")
    return missing


def validate_plan(d: dict, tool_names: set) -> list:
    """杀幻觉工具:steps 为空报错;任一 step 的 tool 非空且 ∉ tool_names → 报"步骤用了不存在的工具 X"。"""
    d = d or {}
    errs = []
    steps = d.get("steps") or []
    if not steps:
        errs.append("steps 为空:Plan 至少要有一步可执行操作")
        return errs
    names = set(tool_names or ())
    for i, s in enumerate(steps, 1):
        tool = str((s or {}).get("tool") or "").strip()
        if tool and tool not in names:
            errs.append(f"步骤{i}用了不存在的工具 {tool}(只能从真实可用工具里选)")
    return errs


# —— 渲染(结构 → 高密度文本)——
def render_report(d: dict) -> str:
    """进展总结结构 → 带标号高密度中文,注入下一轮 planner(沿用 _summarize_round 的四段骨架)。"""
    d = d or {}
    lines = [f"① 已确认算法/校验逻辑:{str(d.get('confirmed_algo') or '').strip() or '(未确认)'}"]
    kd = d.get("key_data") or []
    if kd:
        lines.append("② 关键数据(地址 → 内容 : 含义):")
        for it in kd:
            it = it or {}
            lines.append(f"   {it.get('addr', '?')} → {it.get('value', '')} : {it.get('meaning', '')}")
    else:
        lines.append("② 关键数据:(暂无)")
    tried = d.get("tried") or []
    if tried:
        lines.append("③ 试过的解法及失败原因:")
        for i, it in enumerate(tried, 1):
            it = it or {}
            lines.append(f"   {i}. {it.get('approach', '')} —— 失败:{it.get('why_failed', '')}")
    else:
        lines.append("③ 试过的解法:(暂无)")
    lines.append(f"④ 当前卡点:{str(d.get('blocker') or '').strip() or '(未说明)'}")
    ns = [str(s).strip() for s in (d.get("next_steps") or []) if str(s).strip()]
    if ns:
        lines.append("⑤ 下一轮建议思路:")
        lines.extend(f"   {i}. {s}" for i, s in enumerate(ns, 1))
    return "\n".join(lines)


def render_plan(d: dict) -> str:
    """Plan 结构 → executor 消费的 Plan 文本(题型/架构/关键线索/关键代码/分步/flag格式)。"""
    d = d or {}
    lines = [f"# 题型: {str(d.get('problem_type') or '').strip() or '(待定)'}"]
    arch = str(d.get("arch") or "").strip()
    if arch:
        lines.append(f"# 架构: {arch}")
    kf = [str(x).strip() for x in (d.get("key_findings") or []) if str(x).strip()]
    if kf:
        lines.append("## 关键线索:")
        lines.extend(f"- {x}" for x in kf)
    kc = d.get("key_code") or []
    if kc:
        lines.append("## 关键代码段(直接据此解题,别重复反编译):")
        for it in kc:
            it = it or {}
            lines.append(f"- {it.get('func', '')} @ {it.get('addr', '')}: {it.get('note', '')}")
    lines.append("## 分步:")
    for i, s in enumerate(d.get("steps") or [], 1):
        s = s or {}
        seg = f"{i}. {s.get('goal', '')}"
        if str(s.get("tool") or "").strip():
            seg += f" [工具: {s['tool']}]"
        if str(s.get("success_criteria") or "").strip():
            seg += f" (成功判据: {s['success_criteria']})"
        lines.append(seg)
    fmt = str(d.get("flag_format") or "").strip()
    if fmt:
        lines.append(f"## flag 格式: {fmt}")
    return "\n".join(lines)


def parse_tool_args(message: dict, name: str) -> dict:
    """从 OpenAI 响应 message 的 tool_calls 里取名为 name 的那次调用的 function.arguments(json 串)→ dict。
    找不到该工具名 / 解析失败 → {}(容错:arguments 已是 dict 时直接返回)。"""
    try:
        for c in (message or {}).get("tool_calls") or []:
            fn = (c or {}).get("function") or {}
            if fn.get("name") == name:
                args = fn.get("arguments")
                if isinstance(args, str):
                    return json.loads(args) or {}
                return args or {}
        return {}
    except Exception:
        return {}


# ============================ L3 上下文压缩:交接摘要 ============================
# Codex 的关键取舍:压缩 prompt 要写成"任务交接"(handoff)而不是"内容概括"。
# 明确告诉模型 progress / decisions / remaining work / critical references 四件事,
# 远比"请总结一下"有效。字段按**五类 compact 失败模式**一一对应:
#   约束丢失     → must_keep_verbatim(原文,禁改写)
#   精确证据丢失 → confirmed[].evidence(artifact#N / 真实地址)
#   失败方案污染 → failed_attempts(独立字段,渲染时标成"已排除"而非结论)
#   目标漂移     → current_goal + confirmed/hypothesis 严格分离
# 另一条铁律:摘要**不孤军作战** —— L3 后台账/facts/用户提示原文照旧由动态尾区承载。
HANDOFF = _fn(
    "context_handoff",
    "上下文将被压缩。写一份**交接摘要**给接着干这道题的下一段会话(不是内容概括):"
    "当前目标、必须原样保留的约束、已确认事实(每条给出证据地址/artifact)、仅是猜测的、"
    "已试过并失败的、下一步动作。已失败的必须写进 failed_attempts,别写成结论。",
    {
        "current_goal": {**_STR, "description": "当前仍在推进的目标(别写已结束的旧目标)"},
        "must_keep_verbatim": {**_STRARR, "description":
                               "必须原样保留的约束:用户提示原文、题面给定的 name/email/明文、flag 格式要求"},
        "confirmed": _objarr(
            {"fact": {**_STR, "description": "已验证的事实(算法/长度/密钥…)"},
             "evidence": {**_STR, "description": "证据位置:真实地址 0x.. 或 artifact#N —— 必须能对上台账"}},
            "已确认事实,每条必须带证据位置(数字/hex 不许凭记忆写)"),
        "hypothesis": _objarr(
            {"guess": {**_STR, "description": "尚未验证的猜测"},
             "how_to_verify": {**_STR, "description": "怎么验证它"}},
            "仅是猜测的(与 confirmed 严格分开,防下一轮把猜测当既定事实)"),
        "failed_attempts": _objarr(
            {"attempt": {**_STR, "description": "试过的解法"},
             "why_failed": {**_STR, "description": "为何失败(乱码/超时/地址错…)"}},
            "已试过并失败的 —— **标成已排除,别写成当前结论**"),
        "next_actions": {**_STRARR, "description": "下一步具体动作(可直接执行,别空话)"},
    },
    ["current_goal", "next_actions"],
)

# 语义锚点:摘要开头固定这一句,人和模型都能一眼认出"这是交接摘要不是真实 user 消息"。
# (Codex 还用它做 is_summary_message 判定以便下次压缩跳过旧摘要;antirev 不需要 ——
#  摘要条目在 exchanges 里带 summary=True 标记,判定走标记不走文本匹配。)
SUMMARY_PREFIX = "【上下文交接摘要】"


def validate_handoff(d: dict, known_evidence: set | None = None) -> list:
    """校验交接摘要。known_evidence 给出时,confirmed[].evidence 必须能在其中对上。

    这条交叉校验是治 P0-4 的关键:5985 实测五轮 summary 把同一段密文长度从 32B 写成
    20B 再写成 25B,planner 按错误长度规划 → replan 永不收敛。台账里的地址/artifact
    是工具真实产出的,拿它当锚点,数字就漂不了。
    """
    d = d or {}
    errs = []
    if not str(d.get("current_goal") or "").strip():
        errs.append("current_goal 为空")
    if not [s for s in (d.get("next_actions") or []) if str(s).strip()]:
        errs.append("next_actions 为空")
    if known_evidence is not None:
        for it in d.get("confirmed") or []:
            ev = str((it or {}).get("evidence") or "").strip()
            if ev and not any(k and k in ev for k in known_evidence):
                errs.append(f"confirmed 的证据 {ev} 在台账里对不上(数字/地址不许凭记忆写,"
                            f"请用台账里真实出现过的地址或 artifact#N)")
    return errs


def render_handoff(d: dict) -> str:
    """交接摘要结构 → 文本。带 SUMMARY_PREFIX 锚点;失败项显式标"已排除"。"""
    d = d or {}
    lines = [SUMMARY_PREFIX, f"## 当前目标\n{str(d.get('current_goal') or '').strip()}"]
    mk = [str(x).strip() for x in (d.get("must_keep_verbatim") or []) if str(x).strip()]
    if mk:
        lines.append("## 必须原样遵守的约束(原文,不得改写)")
        lines.extend(f"- {x}" for x in mk)
    cf = d.get("confirmed") or []
    if cf:
        lines.append("## 已确认事实(带证据位置,可直接采信)")
        for it in cf:
            it = it or {}
            lines.append(f"- {it.get('fact', '')}  [证据: {it.get('evidence', '?')}]")
    hy = d.get("hypothesis") or []
    if hy:
        lines.append("## 仅是猜测(**未验证,别当事实用**)")
        for it in hy:
            it = it or {}
            lines.append(f"- {it.get('guess', '')} → 验证方式: {it.get('how_to_verify', '')}")
    fa = d.get("failed_attempts") or []
    if fa:
        lines.append("## 已排除的解法(**试过且失败,别重走**)")
        for it in fa:
            it = it or {}
            lines.append(f"- {it.get('attempt', '')} —— 失败原因: {it.get('why_failed', '')}")
    na = [str(x).strip() for x in (d.get("next_actions") or []) if str(x).strip()]
    if na:
        lines.append("## 下一步动作")
        lines.extend(f"{i}. {x}" for i, x in enumerate(na, 1))
    return "\n".join(lines)
