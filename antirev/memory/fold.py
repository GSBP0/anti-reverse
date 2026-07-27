"""内容感知折叠 / 无损分页 / 有界化 —— 全部纯函数,无状态、不依赖 store。

拆自 context.py:把"怎么把大文本压小又不丢信息"这件事独立出来。三者分工:
- _fold_repeats: 折叠连续同类行(治密度)。花指令几百个重复 pass 压成两行,不同的行全留。
- paginate:      对折叠后文本按页无损切分,供 recall 逐页取全。
- _clip_big:     进上下文的默认视图有界化(先折叠,仍超限才保头尾兜底)。

这一层属于**入口截断**(L0):压缩发生在内容进入消息历史之前,也就是被 prompt cache
记住之前 —— 所以它不破坏任何已有缓存。这是 Codex 与 Claude Code 共同的做法。
"""
from __future__ import annotations
import json
import re

_ADDR_PREFIX = re.compile(r"^\s*0x[0-9a-fA-F]+\s+")


def _norm_line(ln: str) -> str:
    """折叠比较键:去掉反汇编行首地址前缀(0x401000  ...)后 strip,让'指令体相同、地址不同'的花指令行判为同类。"""
    return _ADDR_PREFIX.sub("", ln).strip()


def _fold_repeats(text: str, min_run: int = 3) -> str:
    """内容感知折叠(治密度,非位置截断):连续 >=min_run 的同类行(归一化后相同)折成'代表行+计数',
    不同的行全保留 —— 无损于信息(花指令的真实变换仍在),有损于冗余(几百重复 pass 压成两行)。
    与位置截断的区别:不按位置砍中间,大算法函数的主体不会被误删。"""
    lines = text.split("\n")
    out, i, n = [], 0, len(lines)
    while i < n:
        key = _norm_line(lines[i])
        j = i + 1
        while j < n and _norm_line(lines[j]) == key:
            j += 1
        run = j - i
        if key and run >= min_run:                     # 空行不折叠(避免压掉排版空白)
            out.append(lines[i])                       # 保留一份代表样本(原文,含地址)
            out.append(f"// ... [× {run} 行同类已折叠 {run - 1} 行;需逐行看用 recall 分页] ...")
        else:
            out.extend(lines[i:j])
        i = j
    return "\n".join(out)


def paginate(text: str, page: int = 1, num: int = 120) -> dict:
    """对(折叠后的)文本按页无损切分:每页 num 行,page 从 1。返回 total_pages/has_next,让模型知道还有没有下一页。
    越界页返回空 text(不报错),空文本返回 0 行 —— 供 recall 逐页取全,替代'一次性回灌几十k全文'。"""
    num = max(1, int(num))
    page = max(1, int(page))
    lines = text.split("\n") if text else []
    total_lines = len(lines)
    total_pages = (total_lines + num - 1) // num
    start = (page - 1) * num
    chunk = lines[start:start + num]
    return {"page": page, "num": num, "total_lines": total_lines,
            "total_pages": total_pages, "text": "\n".join(chunk),
            "has_next": start + num < total_lines}


def recall_view(full_text: str, page: int = 1, num: int = 120) -> dict:
    """recall 的分页视图:从 artifact 全文提取可读代码(伪代码优先,其次反汇编),折叠冗余后按页返回。
    非反编译类 artifact(无 pseudocode/disasm)回退为对全文分页 —— 一律无损、可逐页翻,替代一次性回灌几十k。

    这是 Manus 式**可逆压缩**的取回端:上下文里只留 artifact#id 引用,需要时按页无损取回。
    比 Codex 的不可逆 middle-truncation 强 —— 那边截掉就真没了。"""
    try:
        obs = json.loads(full_text) if full_text else {}
    except Exception:
        obs = None
    code = ""
    if isinstance(obs, dict):
        code = obs.get("pseudocode") or obs.get("disasm") or ""
    return paginate(_fold_repeats(code or (full_text or "")), page, num)


def _clip_big(s: str, limit: int = 8000) -> str:
    """进上下文的默认视图有界化:先 _fold_repeats 折叠冗余(治密度),折叠后仍超 limit 才保头尾兜底
    (保证不撑爆工作区)。真超大时兜底截断,但中间可用 recall 分页无损取回。"""
    if not s:
        return s
    folded = _fold_repeats(s)
    if len(folded) <= limit:
        return folded
    return (folded[:limit * 2 // 3] +
            f"\n... [折叠后仍超长,省略中间 {len(folded) - limit} 字符;需全文用 recall(可 page/num 分页)] ...\n" +
            folded[-limit // 3:])
