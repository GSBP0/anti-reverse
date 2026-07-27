"""渐进式上下文压缩 L1/L2/L3。

分层(照 Claude Code 的五层,裁剪到本地端点可实现的三层):
- L1 micro_compact:规则驱动,把超出保护窗的 tool 结果换成 artifact 引用。**零 LLM 成本**。
- L2 drop_steps:  语义驱动,模型主动指定丢弃哪些无关步骤(整轮移除)。零 LLM 成本。
- L3 (在 ContextManager.compact_history):结构化交接摘要替换历史。一次 LLM 调用。
原则是"越轻量越先执行" —— 能用灭火器解决的,就不要叫消防车。

共同的缓存纪律 —— **决策冻结**:每处替换只发生一次、结果字节此后不变。
Claude Code 的教训是若第 5 轮突然改写第 2 轮的内容,第 2 轮之后所有 token 的 KV 全部作废;
mlx 侧同理(PromptTrie 靠逐字节前缀匹配)。所以下面所有替换都写回 exchanges 并打标记,
不在每次 build_messages 时重算。

本地端点没有 Anthropic 的 cache_edits(让服务端在 KV 里用 Attention Mask 遮蔽、消息数组
一个字节不改),所以 L1 只能走"写时修改 + 冻结"这条路,做不到零缓存损失 ——
但一次性代价换长期稳定仍然划算。
"""
from __future__ import annotations

# 保护最近几步的工具结果全文。antirev 单次反编译进上下文约 8000 字符,
# K=3 约合 24k 字符 ≈ 9k token,在 60k 工作区内可控,又够模型看清刚做的事。
PROTECT_RECENT_STEPS = 3

# **模型主动取回的内容受保护**:recall/recall_knowledge 是模型显式表达的信息需求
# ("我需要重看这段算法")。把它压回引用等于否定模型的判断,而且它多半会立刻再 recall 一次
# —— 白耗步数、还可能撞上断环守卫。所以这两类结果 pin 住,只保护最近 N 次(防无限累积)。
_PINNED_TOOLS = {"recall", "recall_knowledge"}
MAX_PINNED_RECALLS = 3

_L1_MARK = "[已压缩·全文见 artifact"


def _ref_artifact_id(ex):
    """该条目被压缩后,引用应指向哪个 artifact。

    recall 的产物本身也会落一份新 artifact,但那是"取回结果"的快照;真正的信息源是
    它**取的那个** artifact。若指向自己,就会套娃成 recall→recall 的引用链,
    模型顺着它取回来的还是同一份摘要。所以 recall 类一律指回 args.artifact_id。
    """
    if ex.get("tool") == "recall":
        src = (ex.get("args") or {}).get("artifact_id")
        if src:
            return src
    return ex.get("art_id")


def micro_compact(exchanges, protect=PROTECT_RECENT_STEPS) -> int:
    """L1:把超出保护窗的 tool 结果替换为 artifact 引用。返回本次压缩的条数。

    只动带 artifact id 的条目(即全文确实已落 SQLite、可 recall 取回的)——没有 id 的
    宁可留着,绝不做不可逆丢弃(这是与 Codex 入口截断的关键差别:那边截掉就真没了)。
    已压过的(带 l1 标记或 _L1_MARK)跳过 → 幂等、冻结。
    **最近 MAX_PINNED_RECALLS 次主动取回(recall/recall_knowledge)一律不压** —— 见 _PINNED_TOOLS。
    """
    if protect < 0:
        protect = 0
    cut = max(0, len(exchanges) - protect)
    # 最近若干次主动取回:pin 住不压(更早的仍可压,否则长跑会无限累积)
    pinned = {i for i, ex in enumerate(exchanges) if ex.get("tool") in _PINNED_TOOLS}
    pinned = set(sorted(pinned)[-MAX_PINNED_RECALLS:])
    n = 0
    for i, ex in enumerate(exchanges[:cut]):
        if ex.get("tool") is None or ex.get("l1") or i in pinned:
            continue
        aid = _ref_artifact_id(ex)
        if not aid:
            continue
        obs = ex.get("obs") or ""
        if _L1_MARK in obs:
            ex["l1"] = True         # 跨轮重建等情形:已是引用,只补标记,不改字节
            continue
        ex["obs"] = (f"OBSERVATION: {_L1_MARK}#{aid},需要时用 "
                     f"recall(artifact_id={aid}) 分页取回] "
                     f"—— 结论已沉淀进下方台账,通常不必重取。")
        ex["l1"] = True
        n += 1
    return n


def drop_steps(exchanges, steps, protect=PROTECT_RECENT_STEPS) -> dict:
    """L2:按 1-based 序号整轮移除历史条目。

    两条硬约束:
    ① 不许丢最近 protect 步 —— 刚做的事被丢掉,模型会原地重做一遍。
    ② 不许丢 summary 条目 —— 那是 L3 的产物,丢了等于失忆。
    整轮移除(assistant.tool_calls + role:tool 一起走)保证配对不断:配对断了端点直接报错,
    这比省 token 要紧得多。

    与 Claude Code 的 SnipCompact 差异:那边用"读时投影"(原始数组不变,发请求时生成视图),
    好处是 UI 能回看完整历史。antirev 的完整历史本来就在 SQLite(artifact),
    UI 完整性已由外部记忆保证,所以直接改数组更简单、熵更低。
    """
    n = len(exchanges)
    keep_from = max(0, n - protect)
    want = set()
    for x in steps or []:
        try:
            i = int(x) - 1
        except (TypeError, ValueError):
            continue
        if 0 <= i < n:
            want.add(i)
    blocked_recent = {i for i in want if i >= keep_from}
    blocked_summary = {i for i in want if exchanges[i].get("summary")}
    doable = want - blocked_recent - blocked_summary
    for i in sorted(doable, reverse=True):
        exchanges.pop(i)
    notes = []
    if blocked_recent:
        notes.append(f"最近 {protect} 步受保护,未丢弃 {sorted(i + 1 for i in blocked_recent)}")
    if blocked_summary:
        notes.append(f"交接摘要不可丢弃,未丢弃 {sorted(i + 1 for i in blocked_summary)}")
    if not want:
        notes.append("给的序号都不在有效范围内(序号从 1 开始,见台账里的步号)")
    return {"dropped": len(doable), "remaining": len(exchanges),
            "note": ";".join(notes) or "已丢弃"}
