"""Planner 节点(§3.2)与 Executor 节点(§3.3)。依赖(client/logger)由 build.py 经闭包注入。

- Planner:先跑确定性预分析(file_info/detect_packer/strings,§5.3),再让模型判题型 + 产出 Plan。
- Executor:用 Plan + 预分析事实做初始输入,跑自研 ReAct Executor(不开 thinking,§3.3)。
- 重规划:Executor 未出 flag → 回 Planner,带上本轮证据重新规划(§3.4)。
"""
from __future__ import annotations
import json
import time

from antirev.react_executor import ReactExecutor
from antirev.tools import analyze_tools as A
from antirev import knowledge
from antirev import config

PLANNER_SYS = (
    "你是逆向题的 Planner。根据确定性预分析判断**题型**并产出简短分步 Plan。\n"
    "题型参考:flag校验 / 加密(异或/TEA/XTEA/XXTEA/RC4/AES/base64/移位) / VM混淆 / 加壳 / 反调试 / 运行时解密。\n"
    "**Executor 的真实可用手段(只能据此规划,严禁建议不存在的工具)**:\n"
    "- 纯静态离线:analyze(格式/架构/壳)、floss(提运行时解密字符串);UPX 脱壳用 terminal 调 `upx -d`\n"
    "- IDA 静态:ida_list_functions、ida_decompile(伪代码+callees+data_refs)、ida_read_bytes(读密文/密钥字节)\n"
    "- angr 符号执行:solve_locate→solve_angr→solve_verify(适合'读输入→逐步比较→到成功分支'型)\n"
    "- unicorn 模拟一段代码;run_python 写解题脚本(内置 antirev.crypto 库 + pwntools/z3/pycryptodome)\n"
    "- **受控 docker 沙箱实跑**:docker_run(--network=none 只读挂载 内存/进程受限)——喂 stdin 实跑、三态验证候选 flag(right/wrong/crash),是**验证候选 flag 的首选强手段**;也可 just-run 观察真实输出\n"
    "- **确定性小工具**:deflower(去花)、unpack_dump(通用脱壳)、pyinstxtract(解PyInstaller+反编译)、dotnet_info/cil(.NET);进制/补码用 terminal 调 python、RSA 分解用 terminal 调 sympy.factorint\n"
    "**⚠ 有受控 docker 沙箱可实跑验证,但无交互式调试器**(x64dbg/OllyDbg/GDB 单步/Ghidra 都没有;别建议下断点、单步)。要观测中间值用 emulate_function 模拟切片、验证候选 flag 用 docker_run 实跑。\n"
    "Plan 要点(务实、简洁、专注、直接):主类型、架构、关键线索、分步(每步目标+**只从上面真实工具里选**+成功判据)、flag格式(**提示非铁律:收录题前缀常是 LitCTF/HDCTF/HZCTF 等,以二进制实际比较/输出串为准,别硬套 NSSCTF{}**)。别灌水,每步可执行。\n"
    "**结构特征路由(慎判'简单')**:花指令(positive sp/call到0xFFFF../jz$+1)→deflower+emulate;VM(大量goto/跳转表)→写Python解释器+emulate对拍;"
    "加壳(高熵/假段名)→terminal 调 upx -d(UPX)或 unpack_dump;OLLVM平坦化(Obfuscator-LLVM/分发器大switch)→emulate(trace_blocks);"
    "反调试(IsDebuggerPresent/ptrace/rdtsc)→emulate桩掉或docker_run实跑。命中这些**别判'简单直读'**。\n\n"
    + knowledge.checklist()
)

_HINT_KW = ("flag", "nssctf", "correct", "wrong", "right", "input", "key",
            "enc", "cipher", "tea", "xtea", "rc4", "aes", "base64", "{")


def _pre_analyze(binary) -> dict:
    fi = A.file_info(binary)
    pk = A.detect_packer(binary)
    strs = A.ascii_strings(binary, min_len=5, limit=2000)
    hints = [s for s in strs if any(k in s.lower() for k in _HINT_KW)]
    return {"file_info": fi, "packer": pk, "hint_strings": hints, "num_strings": len(strs)}


def _fmt_pre(pre) -> str:
    return json.dumps(pre, ensure_ascii=False, indent=1)


def _read_description(binary) -> str:
    """从二进制路径向上找题面 description.md 并读入(bug6:此前 solve 只收 binary、题面从不进模型 →
    4232 的 name/email 就在题面却只能瞎猜、提交自造 hash)。返回截断后的题面文本,找不到则空串。"""
    from pathlib import Path
    try:
        p = Path(binary).resolve()
    except Exception:
        return ""
    for up in [p.parent, *p.parents][:6]:
        f = up / "description.md"
        if f.exists():
            try:
                return (f.read_text(errors="ignore").strip())[:3000]
            except Exception:
                return ""
    return ""


def make_planner(client, logger=None):
    def planner_node(state):
        binary = state["binary"]
        try:
            pre = state.get("pre_analysis") or _pre_analyze(binary)
        except Exception:
            pre = {"file_info": {}, "packer": {}, "hint_strings": [], "num_strings": 0}
        replan = state.get("replan_count", 0)
        parts = [f"## 确定性预分析\n{_fmt_pre(pre)}"]
        desc = _read_description(binary)   # 题面注入(bug6):name/email/明文/flag格式/提示常在此,优先于瞎猜
        if desc:
            parts.insert(0, f"## 📄 题面 description.md(**题目已知信息:可能含 name/email/明文/flag 格式/提示,"
                            f"务必优先利用、别去猜**):\n{desc}\n")
        # 人工干预(human-in-the-loop):用户提示置顶,规划最高优先级采纳(避免每轮重规划又锚回错误点)
        run_id = getattr(logger, "run_id", None)
        if run_id:
            try:
                hp = config.LOG_DIR / f"{run_id}.hint"
                if hp.exists():
                    h = hp.read_text(errors="ignore").strip()
                    if h:
                        parts.insert(0, f"## ⚠️⚠️ 用户提示(**最高优先级,规划务必据此,别再走老思路**):\n{h}\n")
            except Exception:
                pass
        if replan and state.get("evidence"):
            last = state["evidence"][-1]
            summary = last.get("summary") or ""
            ledger = last.get("ledger") or ""
            trace = last.get("trace") or []
            parts.append(f"\n## 第{replan}次重规划:上一轮({last.get('steps')}步)未解出。")
            if summary:     # ★上一轮 executor 自己写的高密度进展总结(搞懂的逻辑/关键数据/试过什么为何失败/卡在哪)
                parts.append(f"\n### 上一轮 executor 的完整进展总结(**这是最关键的输入,据此规划**):\n{summary}")
            if ledger:      # 跨轮记忆:所有轮次工具调用的持久台账(函数地图/已读字节/解题尝试)
                parts.append(f"\n### 工具调用持久台账(函数图/已读字节/尝试,别重查已有的):\n{ledger}")
            decompiles = last.get("decompiles") or ""
            if decompiles:  # 全量反编译:planner 通读理解算法,在 Plan 里只精选关键代码段(压缩上下文,防 executor 反编译累积爆炸)
                parts.append(f"\n### 上一轮所有反编译/反汇编全文(**通读理解算法后,在 Plan 里只摘录对解题关键的代码段**——"
                             f"丢弃花指令垃圾、无关函数、decoy 提示语;标注函数名+地址):\n{decompiles}")
            if trace:  # 完整 executor 操作历史(用户要求:planner 读完整上下文,不止最近几步)
                parts.append("\n### 上一轮 executor 完整操作历史(逐步):\n" + "\n".join(f"  {t}" for t in trace))
            parts.append("\n请**基于上面台账里已知的信息**换一个不同思路/工具/参数改进计划(别重复失败路径)。"
                         "如密码题解出乱码→换 endian/rounds;angr 超时→改读算法写 run_python;"
                         "找不到函数→ida_list_functions;数据读错→按 data_refs 真实地址。"
                         "台账里已反编译的函数别再反编译,直接据其签名/callees 深入或动手解题。"
                         "\n**Plan 必须包含从上面反编译精选的『关键代码段』**(只留解题核心逻辑的那个函数/那几行、标注地址),"
                         "供下一轮 executor 直接据此动手解题、不必重新反编译一堆函数(这是压缩上下文的关键)。")
        parts.append("\n据此判断题型并产出 Plan(**Plan 正文精炼,控制在 1 万字符内**)。")
        user_msg = "\n".join(parts)
        # B2③:给 planner 输入设界(此前只挡输出、不挡输入 → 4052 类顶爆)。超 in_budget 则中段省略、保尾部"请据此规划"指令。
        est_prompt_tok = (len(PLANNER_SYS) + len(user_msg)) // 3
        plan_max = max(2000, min(6000, 60000 - est_prompt_tok))   # ≤6000token≈10k字符
        in_budget = max(30000, (60000 - plan_max) * 3 - len(PLANNER_SYS))
        if len(user_msg) > in_budget:
            user_msg = (user_msg[: in_budget * 3 // 4]
                        + "\n\n...[输入过长,已省略中段反编译;完整用 recall 分页取]...\n\n"
                        + user_msg[-in_budget // 4:])
            est_prompt_tok = (len(PLANNER_SYS) + len(user_msg)) // 3
            plan_max = max(2000, min(6000, 60000 - est_prompt_tok))
        # planner 开 thinking(用户要求;温度 0.4 由 client 自带);timeout=600(重规划要通读全量反编译,输入大)
        plan = client.complete([{"role": "system", "content": PLANNER_SYS},
                                {"role": "user", "content": user_msg}],
                               max_tokens=plan_max, timeout=600)
        # C3:追一次强制 emit_plan 把 free-text 结构化(缺字段/幻觉工具→重生成一次;think+tools 崩或失败→回退 free-text)
        plan_steps = []      # 结构化步骤 → executor 侧尾部 TODO 复述(拿不到就不渲染 TODO)
        try:
            from antirev.tools.report_schema import EMIT_PLAN, validate_plan, render_plan, parse_tool_args
            from antirev.tools.registry import TOOL_NAMES
            msgs = [{"role": "system", "content": PLANNER_SYS},
                    {"role": "user", "content": user_msg
                     + "\n\n上面是你的分析,现在调用 emit_plan 输出结构化 Plan(steps[].tool 必须是真实工具名):\n" + (plan or "")}]
            force = {"type": "function", "function": {"name": "emit_plan"}}
            for _ in range(2):
                m = client.complete_tools(msgs, max_tokens=plan_max, timeout=600,
                                          tools=[EMIT_PLAN], tool_choice=force)
                if m is None:
                    break
                d = parse_tool_args(m, "emit_plan")
                errs = validate_plan(d, TOOL_NAMES)
                if not errs:
                    plan = render_plan(d)
                    plan_steps = d.get("steps") or []
                    break
                msgs.append({"role": "user", "content": f"Plan 有误:{errs}。修正后重新 emit_plan(只用真实工具名)。"})
        except Exception:
            pass
        if logger:
            logger.event("plan_md", replan=replan, plan=plan)
        return {"pre_analysis": pre, "plan": plan, "plan_steps": plan_steps,
                "status": "executing"}
    return planner_node


def make_executor(client, logger=None, max_steps=25, deadline=None, db_path=None,
                  stuck_seconds=None, progress=None):
    def executor_node(state):
        binary = state["binary"]
        remaining = (deadline - time.time()) if deadline else None
        if remaining is not None and remaining <= 5:      # 全局预算用尽
            return {"status": "stuck", "replan_count": state.get("replan_count", 0) + 1}
        _desc = _read_description(binary)   # 题面注入(bug6):executor 也要看到题面给的 name/email/提示
        _desc_block = f"## 📄 题面 description.md(**题目已知信息,务必利用、别猜**):\n{_desc}\n\n" if _desc else ""
        task = (f"题目文件: {binary}\n\n{_desc_block}## 预分析\n{_fmt_pre(state.get('pre_analysis', {}))}\n\n"
                f"## Plan\n{state.get('plan', '')}\n\n按 Plan 解出 flag,拿到后用 FINAL 输出。")
        ex = ReactExecutor(binary, client=client, logger=logger, max_steps=max_steps,
                           time_budget=remaining, db_path=db_path,   # 跨轮共享缓存 db_path
                           stuck_seconds=stuck_seconds, progress=progress)  # 跨轮共享 stuck 追踪
        ex.plan_steps = state.get("plan_steps") or []   # 尾部 TODO 复述用(Manus 注意力锚定)
        result = ex.run(task)
        ev = list(state.get("evidence", []))
        ev.append({"replan": state.get("replan_count", 0), "steps": result.get("steps"),
                   "flag": result.get("flag"), "trace": result.get("trace"),
                   "ledger": result.get("ledger"), "summary": result.get("summary"),
                   "decompiles": result.get("decompiles"), "last_state": result.get("state")})
        upd = {"executor_result": result, "evidence": ev}
        if result.get("flag"):
            upd["flag"], upd["status"] = result["flag"], "done"
        else:
            upd["status"] = "stuck"
            upd["replan_count"] = state.get("replan_count", 0) + 1
        return upd
    return executor_node


def make_router(max_replan=9, deadline=None, stuck_seconds=None, progress=None):
    def route_after_executor(state):
        if state.get("flag"):
            return "done"
        if deadline and time.time() > deadline:      # 全局时间预算到点
            return "fail"
        if stuck_seconds and progress and time.time() - progress.get("last", time.time()) > stuck_seconds:
            return "fail"                            # 10min无新进展,提前判失败
        # replan 空转熔断:连续 6 轮既无解题产出(verified/候选/flag)**又**台账停止增长(不再学到新东西)→ 停止空耗。
        # 两个条件缺一不可:只看"无产出"会误杀慢热题(3790 需 ~7 轮 90 步才解出、4232 亦然,
        # 早先 4 轮阈值把它们从 done 打成 stuck);台账还在长 = 仍在获取新信息,给它继续。
        ev = state.get("evidence", [])
        if len(ev) >= 6:
            recent = ev[-6:]

            def _sig(e):
                st = e.get("last_state") or {}
                vf = st.get("verified")
                return (len(vf) if vf else 0, bool(st.get("candidate")), bool(e.get("flag")))

            no_output = all(_sig(e) == (0, False, False) for e in recent)
            lens = [len(e.get("ledger") or "") for e in recent]
            stagnant = (max(lens) - min(lens)) < 200      # 台账几乎没长 = 纯空转
            if no_output and stagnant:
                return "fail"
        if state.get("replan_count", 0) <= max_replan:
            return "replan"
        return "fail"
    return route_after_executor
