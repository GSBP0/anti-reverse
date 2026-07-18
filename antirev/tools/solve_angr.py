"""solve.angr(§5.2 核心):符号执行自动求 flag。探索到 find、避开 avoid、约束求解出输入。

**通用策略组合(portfolio),不针对单题**:同一 angr 工程内依次尝试多种起始配置,用时间片切分,
谁先解出用谁 —— 既能应对"从 PE/ELF 入口起会淹没在 CRT/libc 初始化里"的通用难题(blank_state
从 main 起跳过它),又保留"必须完整初始化"题目的兜底(full_init_state 从入口起)。

在**受管子进程**跑(§7.2/§11):wall-clock 超时 + 每策略时间片 + 活跃状态上限(防路径爆炸)。
返回 {found:bool, stdin:str, strategy?:str, error?:str}。
"""
from __future__ import annotations
import json
import sys
import textwrap

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated

_DRIVER = textwrap.dedent(r'''
    import sys, json, time, logging
    import angr, claripy
    logging.getLogger("angr").setLevel("ERROR")
    logging.getLogger("cle").setLevel("ERROR")
    logging.getLogger("pyvex").setLevel("ERROR")

    p = json.loads(sys.argv[1])
    n = int(p["stdin_len"])
    max_states = int(p.get("max_states", 200))
    budget = float(p.get("budget", 100.0))
    proj = angr.Project(p["binary"], auto_load_libs=False)

    # 策略顺序:先快(blank@main 跳 CRT),后通用(full@entry)。仅有 start_addr 时才含前者。
    strategies = (["blank_main"] if p.get("start_addr") else []) + ["full_entry"]
    slice_t = budget / len(strategies)

    def build_state(strat, flag, stdin):
        if strat == "blank_main":
            return proj.factory.blank_state(addr=int(p["start_addr"]), stdin=stdin,
                                            add_options={angr.options.LAZY_SOLVES})
        if p["input_kind"] == "stdin":
            return proj.factory.full_init_state(stdin=stdin)
        return proj.factory.full_init_state(args=[p["binary"], flag])

    result = {"found": False, "stdin": ""}
    for strat in strategies:
        flag = claripy.BVS("flag", 8 * n)
        stdin = angr.SimFileStream(name="stdin", content=flag, has_end=True)
        try:
            st = build_state(strat, flag, stdin)
        except Exception as e:
            result = {"found": False, "stdin": "", "error": f"{strat}: {e!r}"[:300]}
            continue
        for byte in flag.chop(8):      # 可打印约束(排空白,防 scanf 提前截断)
            st.solver.add(claripy.And(byte >= 0x21, byte <= 0x7e))
        simgr = proj.factory.simulation_manager(st)
        deadline = time.time() + slice_t

        def _step(sm, _dl=deadline):
            if time.time() > _dl:                       # 本策略时间片用尽 → 收摊,换下一策略
                sm.move(from_stash="active", to_stash="_timeout", filter_func=lambda s: True)
            elif len(sm.active) > max_states:           # 活跃态封顶,防内存爆炸
                sm.stashes["active"] = sm.active[:max_states]
            return sm

        try:
            simgr.explore(find=p["find"], avoid=p.get("avoid", []), num_find=1, step_func=_step)
        except Exception as e:
            result = {"found": False, "stdin": "", "error": f"{strat} explore: {e!r}"[:300]}
            continue
        if simgr.found:
            s = simgr.found[0]
            data = (s.posix.dumps(0) if p["input_kind"] == "stdin"
                    else s.solver.eval(flag, cast_to=bytes))
            result = {"found": True, "stdin": data.decode("latin1"), "strategy": strat}
            break

    print(json.dumps(result))
''')


def solve_angr(binary, find, avoid=None, input_kind="stdin", stdin_len=32,
               timeout=None, max_states=None, start_addr=None) -> dict:
    timeout = timeout or config.ANGR_TIMEOUT
    params = {
        "binary": str(binary), "find": [int(x) for x in find],
        "avoid": [int(x) for x in (avoid or [])],
        "input_kind": input_kind, "stdin_len": int(stdin_len),
        "max_states": int(max_states or config.ANGR_MAX_STATES),
        "start_addr": int(start_addr) if start_addr else None,
        "budget": max(10.0, timeout - 8),   # 内部预算略小于子进程硬超时,好在被杀前打印结果
    }
    r = run_isolated([sys.executable, "-c", _DRIVER, json.dumps(params)], timeout=timeout)
    if r.timed_out:
        return {"found": False, "stdin": "", "error": "angr timeout"}
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        return {"found": False, "stdin": "", "error": (r.stderr or r.stdout)[-1000:]}
