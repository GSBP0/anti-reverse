"""solve.angr(§5.2 核心):符号执行自动求 flag。探索到 find、避开 avoid、约束求解出输入。

angr 跑在**受管子进程**里(§7.2/§11):wall-clock 超时(subprocess) + 活跃状态上限(防路径爆炸)。
崩溃/超时 → 结构化返回,不拖垮主循环。返回 {found:bool, stdin:str, error?:str}。
"""
from __future__ import annotations
import json
import sys
import textwrap

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated

_DRIVER = textwrap.dedent(r'''
    import sys, json, angr, claripy, logging
    logging.getLogger("angr").setLevel("ERROR")
    logging.getLogger("cle").setLevel("ERROR")
    p = json.loads(sys.argv[1])
    n = int(p["stdin_len"])
    max_states = int(p.get("max_states", 200))
    proj = angr.Project(p["binary"], auto_load_libs=False)

    flag = claripy.BVS("flag", 8 * n)
    if p["input_kind"] == "stdin":
        st = proj.factory.full_init_state(
            stdin=angr.SimFileStream(name="stdin", content=flag, has_end=True))
    else:  # argv
        st = proj.factory.full_init_state(args=[p["binary"], flag])
    # 可打印约束:帮收敛、给 ASCII 解(唯一解题目不受影响)
    for byte in flag.chop(8):
        st.solver.add(claripy.Or(byte == 0x0a, claripy.And(byte >= 0x20, byte <= 0x7e)))

    simgr = proj.factory.simulation_manager(st)

    def _cap(sm):
        if len(sm.active) > max_states:      # 活跃态封顶,防内存爆炸
            sm.stashes["active"] = sm.active[:max_states]
        return sm

    simgr.explore(find=p["find"], avoid=p.get("avoid", []), num_find=1, step_func=_cap)
    if simgr.found:
        data = simgr.found[0].posix.dumps(0) if p["input_kind"] == "stdin" \
               else simgr.found[0].solver.eval(flag, cast_to=bytes)
        print(json.dumps({"found": True, "stdin": data.decode("latin1")}))
    else:
        print(json.dumps({"found": False, "stdin": ""}))
''')


def solve_angr(binary, find, avoid=None, input_kind="stdin", stdin_len=32,
               timeout=None, max_states=None) -> dict:
    params = {
        "binary": str(binary), "find": [int(x) for x in find],
        "avoid": [int(x) for x in (avoid or [])],
        "input_kind": input_kind, "stdin_len": int(stdin_len),
        "max_states": int(max_states or config.ANGR_MAX_STATES),
    }
    r = run_isolated([sys.executable, "-c", _DRIVER, json.dumps(params)],
                     timeout=timeout or config.ANGR_TIMEOUT)
    if r.timed_out:
        return {"found": False, "stdin": "", "error": "angr timeout"}
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        return {"found": False, "stdin": "", "error": (r.stderr or r.stdout)[-1000:]}
