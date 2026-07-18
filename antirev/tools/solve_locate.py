"""solve.locate_targets(§5.2):确定性推导 angr 的 find/avoid,别让弱模型猜地址。

做法:pwntools 在 ELF 可加载段里大小写不敏感地定位成功/失败关键词串的**虚拟地址**
(不依赖 IDA 的字符串检测),再让 IDA 取该地址的 xref → 引用点就是成功/失败**分支地址**。
返回 {find:[ea...], avoid:[ea...], evidence:[...]}。
"""
from __future__ import annotations
import re

from antirev import config
from antirev.tools.ida_tools import IdaSession


def _iter_keyword_vaddrs(binary, keywords):
    """产出 (vaddr, matched_text):关键词在可加载段中出现处的虚拟地址(大小写不敏感)。"""
    from pwn import ELF
    e = ELF(binary, checksec=False)
    pat = re.compile(b"|".join(re.escape(k.encode()) for k in keywords), re.I)
    seen = set()
    for seg in e.iter_segments():
        if seg.header.p_type != "PT_LOAD":
            continue
        base = seg.header.p_vaddr
        for m in pat.finditer(seg.data()):
            va = base + m.start()
            if va not in seen:
                seen.add(va)
                yield va, m.group().decode("latin1")


def locate_targets(binary: str) -> dict:
    find, avoid, evidence = [], [], []
    succ = list(_iter_keyword_vaddrs(binary, config.SUCCESS_KEYWORDS))
    fail = list(_iter_keyword_vaddrs(binary, config.FAIL_KEYWORDS))
    with IdaSession(binary) as ida:
        for bucket, hits, kind in ((find, succ, "success"), (avoid, fail, "fail")):
            for va, text in hits:
                for x in ida.xrefs_to(va):
                    bucket.append(x["frm"])
                    evidence.append({"string": text, "string_addr": va,
                                     "ref": x["frm"], "kind": kind})
    return {"find": sorted(set(find)), "avoid": sorted(set(avoid)), "evidence": evidence}
