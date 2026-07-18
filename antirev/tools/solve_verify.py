"""solve.verify(§3.3/§5.2):候选回验——强成功判据。

把候选喂回二进制自身逻辑,确认走到 accept(find)而非 reject(avoid),而不是只看 flag 格式
(格式对 ≠ 真 flag,尤其 angr 求出的输入可能只"能到达目标地址")。MVP 用 angr 具体执行
(复用其 syscall 模型,稳健);§5.2 的 unicorn 片段模拟版列为后续优化。无 find 时降级格式校验并标注风险。
返回 {accepted:bool, method:str, warning?:str}。
"""
from __future__ import annotations
import json
import re
import sys
import textwrap

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated

_DRIVER = textwrap.dedent(r'''
    import sys, json, angr, logging
    logging.getLogger("angr").setLevel("ERROR")
    logging.getLogger("cle").setLevel("ERROR")
    p = json.loads(sys.argv[1])
    proj = angr.Project(p["binary"], auto_load_libs=False)
    cand = p["candidate"].encode()
    st = proj.factory.full_init_state(
        stdin=angr.SimFileStream(name="stdin", content=cand, has_end=True))
    simgr = proj.factory.simulation_manager(st)
    avoid = [p["avoid"]] if p.get("avoid") is not None else []
    simgr.explore(find=[p["find"]], avoid=avoid)
    print(json.dumps({"accepted": bool(simgr.found)}))
''')

_DEFAULT_FLAG_RE = r"^[A-Za-z0-9_]+\{.*\}$"


def verify_candidate(binary, candidate, find=None, avoid=None,
                     flag_regex=_DEFAULT_FLAG_RE) -> dict:
    if find is not None:
        params = {"binary": str(binary), "candidate": candidate,
                  "find": int(find), "avoid": int(avoid) if avoid is not None else None}
        r = run_isolated([sys.executable, "-c", _DRIVER, json.dumps(params)],
                         timeout=config.ANGR_TIMEOUT)
        if not r.timed_out and r.stdout.strip():
            try:
                out = json.loads(r.stdout.strip().splitlines()[-1])
                return {"accepted": bool(out["accepted"]), "method": "angr-concrete"}
            except Exception:
                pass
    # 降级:仅格式校验,标注假阳性风险
    ok = bool(re.match(flag_regex, candidate))
    return {"accepted": ok, "method": "format-only",
            "warning": "未经二进制自验,存在假阳性"}
