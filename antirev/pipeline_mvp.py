"""§14 step 1 的无模型验收流水线:decompile/list → locate_targets → angr → verify。

证明工具链 + 内存闭环,与模型解耦(模型端到端见 executor_mvp.py)。返回
{flag, verified, steps}。这是 MVP 的核心里程碑:确定性四工具端到端出 flag 并回验。
"""
from __future__ import annotations

from antirev.tools.ida_tools import IdaSession
from antirev.tools.solve_locate import locate_targets
from antirev.tools.solve_angr import solve_angr
from antirev.tools.solve_verify import verify_candidate


def run_pipeline(binary: str, stdin_len: int = 32, logger=None) -> dict:
    steps = []

    def _log(**e):
        steps.append(e)
        if logger:
            logger.event("pipeline_step", **e)

    with IdaSession(binary) as ida:
        fns = ida.list_functions()
    _log(step="ida.list_functions", result=f"{len(fns)} functions")

    tgt = locate_targets(binary)
    _log(step="solve.locate_targets",
         find=[hex(x) for x in tgt["find"]], avoid=[hex(x) for x in tgt["avoid"]])
    if not tgt["find"]:
        return {"flag": None, "verified": False, "steps": steps,
                "error": "no find target located"}

    sol = solve_angr(binary, find=tgt["find"], avoid=tgt["avoid"],
                     input_kind="stdin", stdin_len=stdin_len,
                     start_addr=tgt.get("func_hint"))
    _log(step="solve.angr", found=sol.get("found"), error=sol.get("error"))
    if not sol.get("found"):
        return {"flag": None, "verified": False, "steps": steps,
                "error": sol.get("error", "angr no solution")}

    candidate = sol["stdin"].split("\x00")[0].strip()
    ver = verify_candidate(binary, candidate, find=tgt["find"][0],
                           avoid=(tgt["avoid"][0] if tgt["avoid"] else None))
    _log(step="solve.verify", accepted=ver["accepted"], method=ver["method"])
    return {"flag": candidate, "verified": ver["accepted"], "steps": steps}
