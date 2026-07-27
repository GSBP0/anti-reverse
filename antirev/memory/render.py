"""结构 → 文本 的渲染层(纯函数):算法指纹、函数分段地图、签名提取。

拆自 context.py。这里只做"把 dict 变成人/模型可读的高密度一行",不持有状态、不决定放哪。
高密度是刻意的:台账要常驻上下文,每个字符都在跟工具全文抢预算 —— 一行指纹顶裸签名十倍信息量。
"""
from __future__ import annotations


def _first_sig(pseudocode: str) -> str:
    """取伪代码里第一行真正的函数签名(跳过 // 注释 / attributes 行)。"""
    for ln in (pseudocode or "").splitlines():
        s = ln.strip()
        if s and not s.startswith("//") and not s.startswith("/*"):
            return s
    return (pseudocode or "").strip()


def _addrs(items) -> list:
    """从 callees/data_refs 列表提取地址(或名字)字符串。"""
    out = []
    for it in items or []:
        if isinstance(it, dict):
            out.append(str(it.get("addr") or it.get("name") or ""))
        else:
            out.append(str(it))
    return [a for a in out if a]


def _parse_addr(x):
    """把 name_or_addr 解析为 int 地址;非 0x 十六进制(如函数名)返回 None(覆盖追踪只认地址)。"""
    try:
        if isinstance(x, int):
            return x
        s = str(x).strip()
        return int(s, 16) if s.lower().startswith("0x") else None
    except Exception:
        return None


def render_fingerprint(feat: dict) -> str:
    """把函数算法骨架(worker 从汇编抽取的 feat)渲染成一行高密度指纹,替代 func_map 的裸签名。
    保留写 solve 所需的常量与结构:输入/循环次数/带立即数的运算(如 xor 0x37)/比较目标/调用/串引用;
    全文仍可 recall 分页。一行 ~80 字符,却顶裸签名十倍信息量。"""
    p = []
    if feat.get("input"):
        p.append("in")
    if feat.get("loops"):
        p.append(f"loop×{feat['loops']}")
    ops = feat.get("ops") or []
    if ops:     # 花指令题可有几百个不同立即数 → 只显示前 10,余标 …+N(防台账单行爆几千字符)
        shown = ", ".join(m if imm is None else f"{m} {imm:#x}" for m, imm in ops[:10])
        p.append("ops=[" + (shown + f", …+{len(ops) - 10}" if len(ops) > 10 else shown) + "]")
    cmp_imms = feat.get("cmp_imms") or []
    if cmp_imms:
        shown = ", ".join(f"{v:#x}" for v in cmp_imms[:8])
        p.append("cmp=[" + (shown + f", …+{len(cmp_imms) - 8}" if len(cmp_imms) > 8 else shown) + "]")
    elif feat.get("cmps"):
        p.append(f"cmp×{feat['cmps']}")
    if feat.get("calls"):
        p.append("calls=[" + ",".join(" ".join(str(c).split()) for c in feat["calls"]) + "]")
    if feat.get("strs"):    # 折叠串内换行/空白(如 Correct\n),保证指纹单行
        p.append("refs=[" + ",".join(" ".join(str(s).split()) for s in feat["strs"]) + "]")
    return " ".join(p) if p else "(无显著特征)"


def render_outline(outline, seen=None) -> str:
    """把函数 outline(分段地图)渲染成 AI/planner 可读的导航文本:每段特征 + ★核心段 + [已看]/[未看]。
    seen=已下钻的 seg_id 集合(None=planner 侧无覆盖信息只显示地图;set() 空集=executor 侧全未看)。核心段优先展示。"""
    if not outline or not outline.get("segments"):
        return ""
    segs = outline["segments"]
    n = len(segs)
    track = seen is not None        # None=无覆盖信息(planner); set()=有覆盖(空集也显示全未看)
    seen = seen or set()
    head = f"{outline.get('addr')} 分{n}段"
    if track:
        head += f", 已看{len(seen)}/{n}, 还有{n - len(seen)}段未下钻"
    lines = [head + ":"]
    for s in sorted(segs, key=lambda x: (not x.get("core"), x.get("id", 0))):
        star = "★" if s.get("core") else " "
        mark = ("[已看]" if s.get("id") in seen else "[未看]") if track else ""
        fp = render_fingerprint(s.get("feat") or {})
        lines.append(f"  [seg{s.get('id')}] {star}{s.get('kind')} "
                     f"@{s.get('start')}-{s.get('end')} ({s.get('n_insn')}insn) {mark}  {fp}")
    return "\n".join(lines)
