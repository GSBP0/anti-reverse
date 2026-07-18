"""solve.locate_targets(§5.2):确定性推导 angr 的 find/avoid,别让弱模型猜地址。

主路径:用 **IDA 的字符串表**(格式无关,PE/ELF/Mach-O 都行,且直接给字符串起始地址)匹配
成功/失败关键词 → 取该地址 xref → 引用点即成功/失败**分支地址**。
兜底(仅 ELF,当 IDA 未把字符串入表时,如极简手工样本):pwntools 原始扫描定位串 vaddr。
返回 {find:[ea...], avoid:[ea...], evidence:[...]}。
"""
from __future__ import annotations
import re

from antirev import config
from antirev.tools.ida_tools import IdaSession


def _match(value, keywords):
    v = value.lower()
    return any(k in v for k in keywords)


def _from_ida_strings(ida):
    find, avoid, evidence = [], [], []
    for s in ida.strings():
        is_fail = _match(s["value"], config.FAIL_KEYWORDS)
        is_succ = _match(s["value"], config.SUCCESS_KEYWORDS)
        if not (is_succ or is_fail):
            continue
        kind = "fail" if is_fail else "success"     # 冲突优先判失败(如 "wrong flag")
        bucket = avoid if is_fail else find
        for x in ida.xrefs_to(s["addr"]):
            bucket.append(x["frm"])
            evidence.append({"string": s["value"], "string_addr": s["addr"],
                             "ref": x["frm"], "kind": kind})
    return find, avoid, evidence


def _from_raw_elf(binary, ida):
    """ELF 兜底:IDA 未把字符串入表时(极简样本),pwntools 原始扫描定位关键词 vaddr → xref。"""
    try:
        from pwn import ELF
        e = ELF(binary, checksec=False)
    except Exception:
        return [], [], []
    find, avoid, evidence = [], [], []

    def scan(keywords, kind, bucket):
        pat = re.compile(b"|".join(re.escape(k.encode()) for k in keywords), re.I)
        for seg in e.iter_segments():
            if seg.header.p_type != "PT_LOAD":
                continue
            base = seg.header.p_vaddr
            for m in pat.finditer(seg.data()):
                va = base + m.start()
                for x in ida.xrefs_to(va):
                    bucket.append(x["frm"])
                    evidence.append({"string": m.group().decode("latin1"),
                                     "string_addr": va, "ref": x["frm"], "kind": kind})

    scan(config.SUCCESS_KEYWORDS, "success", find)
    scan(config.FAIL_KEYWORDS, "fail", avoid)
    return find, avoid, evidence


def locate_targets(binary: str) -> dict:
    with IdaSession(binary) as ida:
        find, avoid, evidence = _from_ida_strings(ida)
        if not find and not avoid:
            f2, a2, e2 = _from_raw_elf(binary, ida)
            find, avoid, evidence = f2, a2, e2
        # 含首个 find 的函数起始(通常是 main/check),供 angr 从此起跳过 CRT
        func_hint = ida.func_start(find[0]) if find else None
    return {"find": sorted(set(find)), "avoid": sorted(set(avoid)),
            "evidence": evidence, "func_hint": func_hint}
