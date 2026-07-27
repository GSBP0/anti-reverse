"""自研 ReAct Executor(§12)——跑在本地端点(mlx_lm.server + qwen3.6-35b-a3b)上。

- **走原生 tool_calls**(2026-07-21 迁移):框架层与模型 chat_template 两层都支持,
  `complete_tools` 发 tools=TOOLS_SCHEMA、`decode_native` 解析结构化 tool_calls。
  THOUGHT 靠 system prompt 强制"先在 content 写一句理由再调工具"保留。
  (旧注释曾写"端点不支持原生 tool_calls",该前提已被源码核实证伪;文本 ACTION 协议与
   随之而来的 TOOL_SPEC/parse_step/_compress_output 均已删除。)
- 模型是 thinking 模型;用 chat_template_kwargs.enable_thinking=false **关思考**(§3.3),实测省 ~16x 延迟。
- 步数不设过紧上限(信任模型自纠);工具/解析出错回喂让模型改。

上下文由 `memory/context.ContextManager` 管:静态 system → 半静态 task/Plan →
append-only 往返 → 动态尾区(台账/TODO)。压力由 L1(≥32k 按需)/L2(模型调 drop_history)/
L3(≥45k 出交接摘要)三层承接,压满 MAX_L3_COMPACTS 才转 planner。按 64k 窗口精算:
65536 - 6144(输出预留) = 59392 prompt 预算。详见 docs/context.md。

两条通用解题路线(不针对单题):
  (A) 读懂算法→写逆运算:ida_decompile 读逻辑 → 若可逆(异或/编码/TEA/XTEA/RC4/移位…),
      ida_read_bytes 取密文/密钥常量 → run_python 写逆运算脚本(内含正向重算自验)算出 flag。
  (B) 符号执行:若是"读输入→比较到达成功分支"型,solve_locate → solve_angr → solve_verify。
"""
from __future__ import annotations
import difflib
import json
import os
import re
import time

import requests

# —— TPS 埋点(诊断"做着做着变慢"):设环境变量 TPS_METRICS_PATH 时,每次mlx调用记录尺寸/耗时/内存 ——
_TPS_PATH = os.environ.get("TPS_METRICS_PATH", "")


def _log_tps(usage, finish_reason, wall_s, n_msgs):
    if not _TPS_PATH:
        return
    try:
        import psutil
        vm = psutil.virtual_memory()
        mem_free_mb, mem_pct = vm.available // (1024 * 1024), vm.percent
    except Exception:
        mem_free_mb = mem_pct = -1
    pt, ct = usage.get("prompt_tokens"), usage.get("completion_tokens")
    rec = {"ts": round(time.time(), 1), "wall_s": round(wall_s, 2),
           "prompt_tokens": pt, "completion_tokens": ct,
           "tps": round(ct / wall_s, 1) if ct and wall_s > 0 else 0,
           "finish": finish_reason, "n_msgs": n_msgs,
           "mem_free_mb": mem_free_mb, "mem_pct": mem_pct}
    try:
        with open(_TPS_PATH, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass

from antirev import config
from antirev import knowledge
from antirev.memory.store import MemoryStore, _canon
from antirev.memory.context import ContextManager, _brief_args
from antirev.tools.ida_tools import IdaSession
from antirev.tools.solve_locate import locate_targets
from antirev.tools.solve_angr import solve_angr as _run_angr
from antirev.tools.solve_verify import verify_candidate
from antirev.tools.solve_unicorn import unicorn_emulate as _unicorn
from antirev.tools.solve_unicorn import emulate_function as _emulate_fn
from antirev.tools.solve_unicorn import solve_stateless_transform as _solve_transform
from antirev.tools.terminal import terminal as _run_terminal
from antirev.tools.run_code import run_python as _run_python
from antirev.tools import analyze_tools as _analyze
from antirev.tools.registry import TOOLS_SCHEMA

SYSTEM_PROMPT = f"""你是逆向 Executor,目标是解出 flag。开局先 analyze 看清格式/架构/是否加壳;若加壳(如 UPX)先 terminal 调 `upx -d` 脱壳。然后按题选两条通用路线之一:
(A) 读懂算法→写逆运算:先 ida_decompile 读 main/校验逻辑,顺 callees 逐层看清算法。若是标准可逆算法
    (异或/base64/移位/TEA/XTEA/XXTEA/RC4/AES…),用 ida_read_bytes 取密文/密钥,再 run_python 调**内置密码库**(别手写):
    - **优先** `from antirev.crypto import smart_decrypt; print(smart_decrypt('xtea', enc_hex, key_hex, hint='NSSCTF'))`
      —— 自动遍历 endian×rounds×delta,取 flag_like=True 的候选(免猜参数,algo 填 tea/xtea/xxtea/rc4)。
    - 其它:`tea_decrypt_bytes/xtea_decrypt_bytes/xxtea_decrypt_bytes/rc4/aes_ecb_decrypt/b64_custom_decode/xor_bytes`。
    - 若 smart_decrypt 全不像 flag → 算法可能是**魔改**,需按伪代码**精确复现**自定义运算再逆。脚本里正向重算自验,print(flag)。
(B) 符号执行:若是"读输入→逐步比较→到达成功分支"型,solve_locate → solve_angr(stdin_len=?) → solve_verify。
(C) 拿到候选 flag 时:优先 docker_run 把它当 stdin 实跑,verdict==right 再 submit_flag(比正向重算更硬的验证);docker 缺失时退回正向重算自验(run_python 里独立取密文+re-encrypt+print VERIFY_OK)。

**关键纪律(血泪教训,务必遵守)**:
- **读懂逻辑就立刻动手**:一旦从伪代码看清了校验/加密逻辑(哪怕是魔改变体),**马上用 run_python 写逆运算求解**,别再反编译更多函数空转 —— 大量失败都是"看懂了却一直在探索没去解"。
- **魔改算法照抄再逆**:非标准算法就按伪代码**逐条精确复现**每步运算(异或/加减/移位/查表/自定义RC4),取硬编码密文+密钥,run_python 里正向重算比对自验,再逆推出 flag。
- **找不到 main / 全是 sub_(无符号)**:**别按地址顺序在无名函数里乱翻**——先 `find_key_functions` 按"像不像校验/加密"打分排序,**优先反编译分数最高的几个**(通常就是校验/加密函数);或 analyze 看入口地址从入口 ida_decompile 顺 callees 往下。
- **魔改算法先抄后译**:看清伪代码里的自定义运算后,**先把关键公式原样抄成注释、再逐行翻译成 Python**——照抄能避免漏掉 `+1`/加密钥/查表偏移等易错细节(大量失败源于凭记忆手写标准算法、把魔改细节丢了)。
- **大函数别盲读全文**:反编译返回带 outline 段图时,先看★核心段在哪,用 `ida_disasm(name_or_addr=段start, end=段end)` 只下钻那段,逐段理解、别整函数刷屏爆上下文;台账会记你看过哪些段。

**每步先在正文(content)用一句 THOUGHT 说清"这步做什么/为什么",然后调用相应工具**(工具见 tools 定义,一步一个;别只在正文里空谈、别只描述不动手)。

**输出风格:务实、简洁、专注、直接**。务实=拿工具结果说话、少空想;简洁=不复述已知、不灌水;专注=一次只推进当前这一步;直接=有结论立刻调工具验证(如直接 run_python)。需要转录公式、写清算法时该写多长写多长(这不算啰嗦),只是别为兜圈子而灌水。

{knowledge.checklist()}

**一旦 run_python 输出了 flag 样式(某前缀{{...}})且你确信是真解(非诱饵、非猜测/爆破哈希)的字符串,就立刻调用 submit_flag 提交它,别再多跑无谓步骤**(每步生成很贵)。**flag 前缀不必是 NSSCTF{{}}——收录题常保留原始前缀(LitCTF/HDCTF/HZCTF/GXY 等),解码或自验通过的串即答案,别因前缀非 NSSCTF 就反复重算否定它**。
**硬性要求:flag 必须是某个工具(通常 run_python)真实 print/输出出来的,不是你猜或编的——凭空编造的 flag 会被系统拒绝**。
密码/编码题尽量正向重算自验(如 re-encrypt(候选,key)==已知密文,或再 encode 一遍==已知串)后再 submit_flag。工具报错或结果是乱码就换方法/换参数(endian/rounds/key)/换算法重试,别放弃、别硬凑。"""

_FLAGISH_RE = re.compile(r"[A-Za-z0-9_]{2,}\{[^}]{2,}\}")   # flag 样式,用于 stuck 进展判定 _is_progress

# L3 原地压缩次数上限。超过说明本轮方向可能就是错的 → 转 planner 换思路,而不是无限压着跑。
MAX_L3_COMPACTS = 2
# —— 上下文预算(按端点真实 64k 窗口精算)——
CONTEXT_WINDOW = 65536           # mlx_lm.server --max-tokens 65536
EXEC_MAX_TOKENS = 6144           # executor 每步输出预留(给足推理/公式转录/解题脚本)
PROMPT_BUDGET = CONTEXT_WINDOW - EXEC_MAX_TOKENS      # = 59392,prompt 的硬上限
# L3 触发阈值:留 ~14k 余量给"压缩请求自身也要带上下文"(Codex 教训 —— handoff 请求
# = 当前上下文 + 3072 输出,45000+3072=48072 < 59392 安全),且压完要能继续跑而非立刻再触发。
L3_TOKEN_THRESHOLD = 45000
# L1 **按需**触发阈值(≈L3 的 71%)。刻意不每步无条件跑 —— 实测(scripts/probe_prefix_cache.py)
# 每步压会让改动点逐步前移、其后最近几步的全文跟着失效,40 步稳态命中率从 78.8% 崩到 28.4%,
# 完全抵消 append-only 的收益。L1 的价值是"延缓 L3",不是持续瘦身,所以只在快撞阈值时出手。
L1_TOKEN_THRESHOLD = 32000


def _is_progress(tool, obs) -> bool:
    """是否算"朝解题前进"的真进展(重置 stuck 计时)。纯探索(反编译/读字节)、乱码/失败尝试都**不**算 ——
    这样"迷路空转"或"反复失败尝试"超 10min 会被判卡在错误方向(§11)。"""
    if not isinstance(obs, dict) or obs.get("error"):
        return False
    if tool == "run_python":
        return bool(_FLAGISH_RE.search(obs.get("stdout") or ""))   # 产出了 flag 样候选才算
    if tool == "solve_angr":
        return bool(obs.get("found"))
    if tool == "solve_verify":
        return bool(obs.get("accepted"))
    if tool == "solve_locate":
        return bool(obs.get("find"))
    return False


def _norm_thought(t: str) -> str:
    """B1:折叠思路比较键——小写 + 抹具体地址(0x..→0x_)+ 压空白,抓'同款推理不同地址'。"""
    t = re.sub(r"0x[0-9a-fA-F]+", "0x_", (t or "").lower())
    return re.sub(r"\s+", " ", t).strip()


def _loop_repeat(sig, tool, nth, loop) -> bool:
    """B1:当前(签名,工具,归一思路)相对上一步 loop 是否算重复。
    exact=同 (tool,canon_args);fuzzy=同工具且思路≥0.9(run_python 因合法迭代豁免 fuzzy)。"""
    exact = tool is not None and sig == loop.get("sig")
    fuzzy = (tool is not None and tool == loop.get("tool") and tool != "run_python"
             and loop.get("nth") and nth
             and difflib.SequenceMatcher(None, nth, loop["nth"]).ratio() >= 0.9)
    return exact or fuzzy


def _strip_py_comments(code):
    """程序化剥掉 run_python 代码里的注释(# 行内/整行)——模型总不听"禁注释",直接强制去掉省token+净化上下文。
    用 tokenize 保证不误删字符串里的 #。解析失败(半截代码等)则原样返回。"""
    import io
    import tokenize
    try:
        toks = [t for t in tokenize.generate_tokens(io.StringIO(code).readline)
                if t.type != tokenize.COMMENT]
        out = tokenize.untokenize(toks)
        # 去行尾空白 + 删纯空白行,进一步压缩
        return "\n".join(ln.rstrip() for ln in out.splitlines() if ln.strip())
    except Exception:
        return code


def decode_native(message):
    """原生 tool_calls 响应 → (kind, tool, args, thought, flag)。kind ∈ {'action','final','none'}。
    thought = content(prompt 强制的一句理由,剥掉模型自带的 'THOUGHT:' 前缀避免叠字);
    submit_flag 调用 → final(tool 记为 submit_flag 便于日志);其余 tool_call → action;
    无 tool_call → none(触发 nudge 提示模型去调工具)。"""
    thought = (message.get("content") or "").strip()
    thought = re.sub(r"^\s*THOUGHT\s*[:：]\s*", "", thought, flags=re.I)   # 剥模型自带前缀
    tcs = message.get("tool_calls") or []
    if tcs:
        fn = tcs[0].get("function") or {}
        name = fn.get("name") or ""
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except Exception:
            args = {}
        if not isinstance(args, dict):
            args = {}
        if name == "submit_flag":
            flag = str(args.get("flag", "")).strip()
            return "final", "submit_flag", {"flag": flag}, thought, flag
        if name == "report_unsolved":
            return "unsolved", "report_unsolved", args, thought, None
        return "action", name, args, thought, None
    return "none", None, None, thought, None


class ChatClient:
    def __init__(self, base_url=None, model=None, think=False, temperature=0.0):
        self.base = (base_url or config.MODEL_BASE_URL).rstrip("/")
        self.model = model or config.MODEL_NAME
        self.think = think
        self.temperature = temperature
        self.api_key = config.MODEL_API_KEY   # 远程 API 认证(config 从 ANTIREV_MODEL_KEY 环境变量取)
        self.last_prompt_tokens = None   # 上一次返回的真实 prompt token(供熔断精确判上下文长度,免字符估算偏差)

    def complete(self, messages, max_tokens=6144, temperature=None, timeout=180, retries=3):
        if temperature is None:      # 不显式传则用 client 自带温度(planner=0.4 / executor=0.35)
            temperature = self.temperature
        body = {"model": self.model, "messages": messages,
                "max_tokens": max_tokens, "temperature": temperature,
                "enable_thinking": self.think}   # 阿里云/兼容端点思考开关
        if not self.think:
            body["chat_template_kwargs"] = {"enable_thinking": False}   # mlx 端点开关(两个都设,各端点认各的)
        # 重试:mlx 服务持续高负载下偶发超时/异常/畸形响应 → 别让整题崩(§11 robustness)
        for attempt in range(retries):
            try:
                t0 = time.time()
                r = requests.post(self.base + "/chat/completions", json=body, timeout=timeout,
                                  headers={"Authorization": f"Bearer {self.api_key}"})
                dt = time.time() - t0
                data = r.json()
                choice = data["choices"][0]
                usage = data.get("usage", {})
                self.last_prompt_tokens = usage.get("prompt_tokens") or self.last_prompt_tokens
                _log_tps(usage, choice.get("finish_reason"), dt, len(messages))
                msg = choice["message"]
                return msg.get("content") or msg.get("reasoning") or ""
            except Exception:
                if attempt < retries - 1:
                    time.sleep(2 * (attempt + 1))
        return ""   # 重试全失败 → 返回空,上层当空输出处理,不崩题

    def complete_tools(self, messages, max_tokens=6144, temperature=None, timeout=180, retries=3,
                       tools=None, tool_choice="auto"):
        """原生 tool_calls 调用。tools 默认 TOOLS_SCHEMA;C3 让 summary/planner 传专用 schema 强约束输出。"""
        if temperature is None:
            temperature = self.temperature
        body = {"model": self.model, "messages": messages,
                "max_tokens": max_tokens, "temperature": temperature,
                "tools": tools or TOOLS_SCHEMA, "tool_choice": tool_choice,
                "enable_thinking": self.think}   # 阿里云/兼容端点思考开关
        if not self.think:
            body["chat_template_kwargs"] = {"enable_thinking": False}   # mlx 端点开关(两个都设,各端点认各的)
        for attempt in range(retries):
            try:
                t0 = time.time()
                r = requests.post(self.base + "/chat/completions", json=body, timeout=timeout,
                                  headers={"Authorization": f"Bearer {self.api_key}"})
                dt = time.time() - t0
                data = r.json()
                choice = data["choices"][0]
                usage = data.get("usage", {})
                self.last_prompt_tokens = usage.get("prompt_tokens") or self.last_prompt_tokens
                _log_tps(usage, choice.get("finish_reason"), dt, len(messages))
                return choice["message"]
            except Exception:
                if attempt < retries - 1:
                    time.sleep(2 * (attempt + 1))
        return None   # 重试全失败 → None,上层跳过本步


class ReactExecutor:
    def __init__(self, binary, client=None, logger=None, max_steps=60, window=4, db_path=None,
                 time_budget=None, stuck_seconds=None, progress=None):
        self.binary = binary
        self.client = client or ChatClient()
        self.logger = logger
        self.max_steps = max_steps
        self.window = window
        self.time_budget = time_budget    # 秒;超预算优雅停止(§11),在子进程硬超时前保住日志
        self.stuck_seconds = stuck_seconds  # 超此秒数无"新进展"(疑似卡错误方向不自纠)→ 提前判失败
        # progress 跨轮共享:{"last": 上次新进展时刻, "seen": 已见过的(工具,摘要)签名集}
        self._progress = progress if progress is not None else {"last": None, "seen": set(),
                                                                "loop": {"sig": None, "tool": None, "nth": "", "n": 0}}
        self.run_id = getattr(logger, "run_id", None) or "exec"
        self.db_path = db_path or ":memory:"
        self.active_binary = binary   # 脱壳后会切到 .unpacked
        self._ida = None              # 常驻 IdaSession(一次分析多次查询,避免每步重开 worker)
        self.plan_steps = []          # 结构化 Plan 步骤(由 graph 注入),供尾部 TODO 复述
        self._ctx = None              # 当轮 ContextManager(供 drop_history 等要改上下文的工具用;
        #                               刻意不进 _dispatch 签名 —— 测试里的 _dispatch 桩是三参)
        self.state = {"find": None, "avoid": None, "candidate": None, "func_hint": None,
                      "verified": set()}   # D1:通过二进制强验证的 flag(solve_verify/stateless/docker right)

    def _get_ida(self):
        """取常驻 IdaSession;进程死了或切了二进制(脱壳)则重开。"""
        from pathlib import Path as _P
        resolved = str(_P(self.active_binary).resolve())
        if self._ida is not None and (self._ida.p is None or self._ida.p.poll() is not None
                                      or self._ida.binary != resolved):
            try:
                self._ida.__exit__(None, None, None)
            except Exception:
                pass
            self._ida = None
        if self._ida is None:
            self._ida = IdaSession(self.active_binary)
            self._ida.__enter__()
        return self._ida

    def _close_ida(self):
        if self._ida is not None:
            try:
                self._ida.__exit__(None, None, None)
            except Exception:
                pass
            self._ida = None

    def _log(self, type, **f):
        if self.logger:
            self.logger.event(type, **f)

    def _summarize_round(self, ctx):
        """C3:强制 report_progress 结构化 + 校验 + 缺字段一次重生成(治 4052 空 summary)。返回渲染文本(向后兼容)。"""
        try:
            from antirev.tools.report_schema import (REPORT_PROGRESS, validate_report,
                                                     render_report, parse_tool_args)
            msgs = ctx.build_messages(SYSTEM_PROMPT, ctx.goal)   # 带完整上下文
            msgs.append({"role": "user", "content":
                "本轮结束未解出。调用 report_progress 汇报进展(必填字段务必具体:已确认算法/关键数据地址+值/试过什么为何失败/卡点/下一步,别空话)。"})
            force = {"type": "function", "function": {"name": "report_progress"}}
            d, miss = {}, ["(未产出)"]
            for _ in range(2):
                m = self.client.complete_tools(msgs, max_tokens=4096, timeout=150,
                                               tools=[REPORT_PROGRESS], tool_choice=force)
                if m is None:
                    break
                d = parse_tool_args(m, "report_progress")
                miss = validate_report(d)
                if not miss:
                    break
                msgs.append({"role": "user", "content": f"字段缺失/空:{miss}。补全后重新调用 report_progress。"})
            self._log("round_summary", summary=d, missing=miss)
            return render_report(d) if d else ""
        except Exception:
            return ""

    def _build_handoff(self, ctx) -> str:
        """L3:让模型写一份交接摘要(强制 context_handoff schema + 与台账交叉校验证据)。

        **压缩请求自身也可能撞上限**(Codex 的教训):此时先做一次激进 L1(protect=1,
        把几乎所有旧工具全文换成 artifact 引用)腾出空间再重试。方向是"压掉最旧的",
        因为从旧端削才保得住 prefix cache。腾完仍失败就返回 "" —— 上层退回转 planner,
        绝不拿半成品摘要覆盖历史。
        """
        try:
            from antirev.tools.report_schema import (HANDOFF, parse_tool_args,
                                                     render_handoff, validate_handoff)
            known = ctx.known_evidence()
            force = {"type": "function", "function": {"name": "context_handoff"}}
            ask = ("上下文即将压缩。调用 context_handoff 写交接摘要给接着干这道题的下一段会话:"
                   "已确认事实必须给出台账里真实出现过的证据地址或 artifact#N;"
                   "试过并失败的写进 failed_attempts(别写成结论);猜测放 hypothesis。")
            for attempt in range(2):
                if attempt == 1:
                    # 首次失败(很可能是压缩请求自己超限)→ 激进 L1 腾空间后重试
                    freed = ctx.micro_compact(protect=1)
                    self._log("handoff_retry_after_l1", freed=freed)
                    if not freed:
                        return ""
                msgs = ctx.build_messages(SYSTEM_PROMPT, ctx.goal)
                msgs.append({"role": "user", "content": ask})
                for _ in range(2):      # 同一份上下文里最多纠错一次(缺字段/证据对不上)
                    m = self.client.complete_tools(msgs, max_tokens=3072, timeout=180,
                                                   tools=[HANDOFF], tool_choice=force)
                    if m is None:
                        break           # 疑似超限 → 跳出内层,走外层的 L1 腾空间重试
                    d = parse_tool_args(m, "context_handoff")
                    errs = validate_handoff(d, known_evidence=known)
                    if not errs:
                        return render_handoff(d)
                    msgs.append({"role": "user",
                                 "content": f"交接摘要有问题:{errs}。修正后重新调用 context_handoff。"})
            return ""
        except Exception:
            return ""

    def _fail(self, ctx, steps, error):
        """统一的失败返回:附带台账 + 全量反编译 + 本轮进展总结(供 planner 完整了解、精选关键代码段)。"""
        return {"flag": None, "steps": steps, "error": error, "state": self.state,
                "trace": ctx.step_notes, "ledger": ctx.ledger_text(),
                "decompiles": ctx.decompile_dump(),
                "summary": self._summarize_round(ctx)}

    def _dispatch(self, tool, args, store):
        b = self.active_binary
        try:
            if tool == "recall":
                art = store.get_artifact(int(args.get("artifact_id")))
                if not art:
                    return {"error": "无此 artifact"}
                from antirev.memory.context import recall_view
                view = recall_view(art["full_text"], args.get("page", 1), args.get("num", 120))
                nxt = (f";还有下一页,翻页 page={view['page'] + 1}" if view["has_next"] else ";已到末页")
                return {"artifact_id": int(args.get("artifact_id")), "tool": art.get("tool"),
                        "hint": f"第{view['page']}/{view['total_pages']}页(共{view['total_lines']}行){nxt}",
                        **view}
            if tool == "recall_knowledge":
                return knowledge.recall(args.get("topic", ""))
            if tool == "drop_history":      # L2:模型主动清理无关历史(经 self._ctx,不改 _dispatch 签名)
                if self._ctx is None:
                    return {"error": "上下文不可用"}
                return self._ctx.drop_history(args.get("steps") or [], args.get("reason", ""))
            # 只读 IDA 工具:命中缓存直接返回(仅未脱壳时,避免用错二进制的缓存)(§6.3)
            if b == self.binary and tool in ("ida_list_functions", "ida_decompile", "ida_disasm",
                                             "ida_read_bytes", "find_key_functions"):
                cached = store.find_cached(self.run_id, tool, args)
                if cached:
                    return json.loads(cached["full_text"])
            if tool == "analyze":
                return {"file_info": _analyze.file_info(b), "packer": _analyze.detect_packer(b)}
            if tool == "floss":
                return _analyze.floss_strings(b)
            if tool == "unicorn_emulate":
                return _unicorn(b, int(args["start"], 0) if isinstance(args["start"], str) else args["start"],
                                int(args["stop"], 0) if isinstance(args["stop"], str) else args["stop"],
                                arch=args.get("arch", "x86_64"), regs=args.get("regs"),
                                mem_writes=args.get("mem_writes"), read_mem=args.get("read_mem"))
            if tool == "emulate_function":
                return _emulate_fn(b, args["start"], args["stop"], input_hex=args.get("input_hex", ""),
                                   input_reg=args.get("input_reg", "rdx"),
                                   read_offset=int(args.get("read_offset", 0)),
                                   read_size=args.get("read_size"), extra_regs=args.get("extra_regs"),
                                   arch=args.get("arch", "x86_64"))
            if tool == "solve_stateless_transform":
                r = _solve_transform(b, args["start"], args["stop"], args["cipher_len"],
                                     cipher_addr=args.get("cipher_addr"),
                                     input_reg=args.get("input_reg", "rdx"), read_offset=args.get("read_offset"),
                                     prefix=args.get("prefix", ""), suffix=args.get("suffix", ""),
                                     arch=args.get("arch", "x86_64"))
                if r.get("verified") and r.get("flag"):
                    self.state.setdefault("verified", set()).add(str(r["flag"]).strip())   # D1
                return r
            if tool == "ida_list_functions":
                fns = self._get_ida().list_functions(args.get("filter"))
                return {"count": len(fns),
                        "functions": [{"addr": hex(f["addr"]), "name": f["name"],
                                       "size": f["size"]} for f in fns]}
            if tool == "find_key_functions":
                fns = self._get_ida().score_functions(int(args.get("top", 12)))
                return {"count": len(fns), "functions": fns}
            if tool == "ida_decompile":
                try:
                    r = self._get_ida().decompile(args["name_or_addr"])
                    return {"pseudocode": r["pseudocode"],
                            "data_refs": r.get("data_refs", []), "callees": r.get("callees", []),
                            "fingerprint_feat": r.get("fingerprint_feat"), "outline": r.get("outline")}
                except Exception as e:
                    # hexrays 反编译失败(如 main "hexrays returned None")→ 自动反汇编兜底,别让模型瞎
                    try:
                        d = self._get_ida().disasm(args["name_or_addr"])
                        return {"pseudocode": None,
                                "note": f"hexrays反编译失败({str(e)}),已自动改为反汇编;据汇编分析逻辑",
                                "disasm": d["disasm"], "callees": d.get("callees", []),
                                "fingerprint_feat": d.get("fingerprint_feat"), "outline": d.get("outline")}
                    except Exception as e2:
                        return {"error": f"decompile失败且disasm也失败: {str(e2)}"}
            if tool == "ida_disasm":
                d = self._get_ida().disasm(args["name_or_addr"], count=int(args.get("count", 80)),
                                           end=args.get("end"))
                return {"addr": d.get("addr"), "name": d.get("name"),
                        "disasm": d["disasm"], "callees": d.get("callees", []),
                        "fingerprint_feat": d.get("fingerprint_feat"), "outline": d.get("outline")}
            if tool == "ida_read_bytes":
                return self._get_ida().get_bytes(args["name_or_addr"], int(args["size"]))
            if tool == "run_python":
                return _run_python(args.get("code", ""), binary=b)   # 不动模型写的代码:注释可锚定公式(§不裁剪, 5985教训)
            if tool == "solve_locate":
                r = locate_targets(b, ida=self._get_ida())   # 复用常驻session,避免开第二个IdaSession撞DB锁(rc=4)
                self.state.update(find=r["find"], avoid=r["avoid"], func_hint=r.get("func_hint"))
                return {"find": r["find"], "avoid": r["avoid"]}
            if tool == "solve_angr":
                find = args.get("find") or self.state["find"]
                if not find:
                    return {"error": "请先 solve_locate 得到 find/avoid"}
                r = _run_angr(b, find=find, avoid=args.get("avoid") or self.state["avoid"] or [],
                              stdin_len=int(args.get("stdin_len", 32)), start_addr=self.state.get("func_hint"))
                if r.get("found"):
                    self.state["candidate"] = r["stdin"].split("\x00")[0].strip()
                return r
            if tool == "solve_verify":
                cand = args.get("candidate") or self.state["candidate"]
                if not cand:
                    return {"error": "无候选,请先 solve_angr"}
                find, avoid = self.state["find"], self.state["avoid"]
                r = verify_candidate(b, cand, find=(find[0] if find else None),
                                     avoid=(avoid[0] if avoid else None))
                r["candidate"] = cand
                if r.get("accepted"):
                    self.state.setdefault("verified", set()).add(str(cand).strip())   # D1
                return r
            if tool == "terminal":
                return _run_terminal(args.get("command", ""))
            # —— 阶段二/三 新增工具(局部 import,按需加载)——
            if tool == "deflower":
                from antirev.tools.deobf import deflower as _df
                return _df(b, args["start"], end=args.get("end"), arch=args.get("arch"))
            if tool == "unpack_dump":
                from antirev.tools.unpack import generic_unpack as _gu
                r = _gu(b, arch=args.get("arch"))
                if r.get("ok") and r.get("out"):
                    self.active_binary = r["out"]      # 后续分析切到 dump 产物(unpack_dump 脱壳后)
                    r["note"] = "已切换到 dump 文件,后续工具在其上分析"
                return r
            if tool == "docker_run":
                from antirev.tools.docker_run import docker_run as _dr
                r = _dr(b, stdin_hex=args.get("stdin_hex", ""), args=args.get("args"))
                if r.get("verdict") == "right" and args.get("stdin_hex"):
                    try:                       # D1:docker 实跑 verdict=right → 候选进 verified
                        self.state.setdefault("verified", set()).add(
                            bytes.fromhex(args["stdin_hex"]).decode("latin1").strip())
                    except Exception:
                        pass
                return r
            if tool == "pyinstxtract":
                from antirev.tools.toolchain import pyinstxtract as _px
                return _px(b)
            if tool == "dotnet_info":
                from antirev.tools.toolchain import dotnet_info as _di
                return _di(b)
            if tool == "dotnet_cil":
                from antirev.tools.toolchain import dotnet_cil as _dc
                return _dc(b, args["method"])
            if tool == "data_provenance":
                return self._get_ida().data_provenance(args["name_or_addr"], int(args.get("size", 16)))
            if tool == "deobf_scan":
                return self._get_ida().deobf_scan()
            if tool == "check_flag":
                from antirev import flag_check
                cand = args.get("flag", "")
                n = self.state.get("check_flag_n", 0) + 1   # 防爆破:限校验次数(先真解出再确认,非枚举工具)
                self.state["check_flag_n"] = n
                if n > 8:
                    return {"verdict": "limit",
                            "advice": "校验次数已用尽(防爆破);请正向重算(re-encrypt==密文)或 docker_run 实跑自验后自行判断再 submit"}
                r = flag_check.verify_for_run(cand, self.run_id)
                if r.get("verdict") == "correct":   # oracle 确认 → 候选进 verified,submit 时 D1 硬门放行
                    self.state.setdefault("verified", set()).add(str(cand).strip())
                return r
            return {"error": f"unknown tool {tool}"}
        except Exception as e:
            return {"error": repr(e)}

    def _break_hint(self, cat, tool, args, ctx, verbose) -> str:
        """B1:断环提示——结合台账给'这些都试过了,换 X'的具体换招。verbose=False 只给简版。"""
        base = f"⚠️ 你已连续重复同一步『{tool}({_brief_args(args)})』且无进展——重复必然得到相同结果,别再来。"
        if not verbose:
            return base + "换一个**不同维度**推进,否则本题将转重规划。"
        tried = "; ".join(a.get("digest", "") for a in ctx.attempts[-4:]) or "(无)"
        funcs = ", ".join(list(ctx.func_map.keys())[:8]) or "(无)"
        reads = ", ".join(ctx.reads.keys()) or "(无)"
        tmpl = {
            "ida_decompile": f"{base}\n已反编译: {funcs}。血泪纪律:**读懂逻辑就立刻 run_python 写逆运算**,别再反编译更多函数。"
                             f"读不懂(花指令/魔改)→ deflower 去花 / emulate_function 跑二进制自身逻辑 / solve_stateless_transform 一键解。",
            "ida_disasm": f"{base}\n已反编译: {funcs}。看懂就动手 run_python;花指令用 deflower。",
            "run_python": f"{base}\n已试: {tried}。换维度:①算法魔改→按伪代码精确复现或 emulate_function 跑二进制自身"
                          f"②密文/密钥地址读错→按 data_refs 真实地址 ida_read_bytes ③换 endian/rounds/字符表/补码(terminal 调 python 算)"
                          f"④暴破/试错多次未果→**回主调用链重审**:find_key_functions 最高分函数可能是被你跳过的真 checker,先反编译它再解(元认知:别在错误维度上死磕)。",
            "solve_angr": f"{base}\n已试: {tried}。符号执行(路线B)走不通→换路线A:ida_decompile 读算法→run_python 写逆运算。",
            "emulate_function": f"{base}\nstart/stop 可能没对齐真实指令边界→先 ida_disasm 核对地址;或改 solve_stateless_transform 自动校准。",
            "ida_read_bytes": f"{base}\n已读: {reads}。拿到密钥/密文就该 run_python 动手解,别反复读同一段。",
            "find_key_functions": f"{base}\n已有排序,别再打分——直接反编译最高分函数并动手解。",
        }
        return tmpl.get(cat, base + "换不同工具/参数/维度推进。")

    def run(self, plan: str):
        store = MemoryStore(self.db_path)
        ctx = ContextManager(store, self.run_id, window=self.window)
        self._ctx = ctx               # 供 drop_history 用
        ctx.set_goal(plan)
        ctx.set_plan_steps(self.plan_steps)
        bad_parse = 0                 # 连续无法解析(常因输出超 max_tokens 被截断成半截 JSON)计数
        seen_kb = set()               # 已注入过的知识库条目(每题每条只即时注一次,免刷屏)
        ctx.load_prior(store)         # 跨轮记忆:从 store 重建本题此前所有轮次的工具调用台账
        start = time.time()
        # 每轮(含replan后)重置stuck计时:新plan=新方向,给executor完整时间执行。
        # planner精选/重规划耗时(可达数分钟)不该算作executor"无进展"而误杀下一轮
        # (2000 round8教训:planner精选出正解emulate,executor却因planner耗时254s累计超stuck、0步被判失败)。
        self._progress["last"] = start
        self.client.last_prompt_tokens = None   # B2②:每轮清陈旧 token 计,免跨轮冻结自杀(4052:round1撑崩后106458冻结→round2小上下文却step1立即熔断0步)
        self._progress.setdefault("loop", {}).update({"sig": None, "tool": None, "nth": "", "n": 0})  # B1:每轮重置轮内断环追踪
        self._progress["explore_n"] = 0   # 每轮重置"连续纯探索"计数(新plan新方向,给机会)
        try:
            for step in range(1, self.max_steps + 1):
                if self.time_budget and time.time() - start > self.time_budget:
                    self._log("time_budget_exceeded", step=step)
                    return self._fail(ctx, step, "超时间预算")
                if self.stuck_seconds and time.time() - self._progress["last"] > self.stuck_seconds:
                    self._log("stuck_no_progress", step=step,
                              secs=int(time.time() - self._progress["last"]))
                    return self._fail(ctx, step, f"{int(self.stuck_seconds // 60)}min无新进展(疑似卡错误方向,提前判失败)")
                # 人工干预(human-in-the-loop):读用户中途丢的提示文件 → 置顶注入上下文(最高优先级,跨轮持续)
                try:
                    _hp = config.LOG_DIR / f"{self.run_id}.hint"
                    if _hp.exists():
                        _h = _hp.read_text(errors="ignore").strip()
                        if _h and _h not in ctx.user_hints:
                            ctx.add_user_hint(_h)
                            self._log("user_hint", step=step, hint=_h)
                            self._progress["last"] = time.time()   # 新提示=新方向,重置stuck计时
                except Exception:
                    pass
                try:
                    messages = ctx.build_messages(SYSTEM_PROMPT, plan)
                    # 上下文压力:优先用 mlx 上一步返回的真实 prompt_tokens(准, 免字符估算偏差);
                    # 首步无前值→字符估算兜底(~2.5字符/token)。
                    approx = self.client.last_prompt_tokens or (sum(len(m.get("content", "")) for m in messages) * 2 // 5)
                    # L1 **按需**:接近阈值才压一次(零 LLM 成本,旧工具全文 → artifact 引用)。
                    # 不每步压 —— 那会让改动点每步前移、把其后最近几步的全文也作废。
                    if approx >= L1_TOKEN_THRESHOLD:
                        freed = ctx.micro_compact()
                        if freed:
                            self._log("l1_compact", step=step, freed=freed, before_tokens=approx)
                            messages = ctx.build_messages(SYSTEM_PROMPT, plan)
                            # 压过之后真实 prompt_tokens 已过时(偏大),改用字符估算
                            approx = sum(len(m.get("content", "")) for m in messages) * 2 // 5
                    if approx >= L3_TOKEN_THRESHOLD:
                        # 先 L3 原地压缩续跑(Codex mid-turn compact:任务不中断),
                        # 压满 MAX_L3_COMPACTS 次仍未解出才转 planner 换思路。
                        if ctx._compact_n < MAX_L3_COMPACTS:
                            summary = self._build_handoff(ctx)
                            if summary:
                                ctx.compact_history(summary)
                                self._log("l3_compact", step=step, approx_tokens=approx,
                                          n=ctx._compact_n)
                                # 压缩后重置 token 基线(Codex BodyAfterPrefix):否则固定前缀
                                # 反复计入同一压缩窗口的预算,刚压完又立刻触发
                                self.client.last_prompt_tokens = None
                                continue
                        self._log("context_limit_replan", step=step, approx_tokens=approx,
                                  source=("real" if self.client.last_prompt_tokens else "estimate"),
                                  compacted=ctx._compact_n)
                        return self._fail(ctx, step,
                                          f"上下文~{approx}token 且已压缩{ctx._compact_n}次,"
                                          f"转 planner 归纳压缩关键代码段")
                    # max_tokens=6144:给足输出空间,不再截断模型的推理/公式转录/解题脚本(§不裁剪原则)。
                    # 靠 prompt 引导"务实简洁专注直接"来控冗长,而非硬砍 max_tokens(硬砍会连 ACTION/公式一起截没)。
                    resp = self.client.complete_tools(messages, max_tokens=EXEC_MAX_TOKENS,
                                                     timeout=300, retries=2)
                    if resp is None:      # 模型调用重试后仍失败 → 跳过本步(不崩题)
                        continue
                    kind, tool, args, thought, flag = decode_native(resp)
                    # has_content 埋点:统计原生模式下 content(强制 THOUGHT)非空率,监测推理链是否真被保留
                    self._log("executor_output", step=step, thought=thought, tool=tool, args=args,
                              has_content=bool((resp.get("content") or "").strip()), ctx_msgs=len(messages))
                    # —— B1 轮内断环守卫(仅拦 action;final/none 各有既有处理)——
                    if kind == "action":
                        loop = self._progress.setdefault("loop", {"sig": None, "tool": None, "nth": "", "n": 0})
                        seen = self._progress.setdefault("seen", set())
                        sig = (tool, _canon(args or {}))
                        nth = _norm_thought(thought)
                        loop["n"] = loop["n"] + 1 if _loop_repeat(sig, tool, nth, loop) else 0
                        loop["sig"], loop["tool"], loop["nth"] = sig, tool, nth
                        if loop["n"] >= 1:            # 第2次同款 → 断环(跳过必然浪费的调用)
                            if loop["n"] >= 3:        # 连续无视 → 升级重规划,防无限空转
                                self._log("loop_escalate_replan", step=step, tool=tool, n=loop["n"])
                                return self._fail(ctx, step, "反复空转、无法自纠 → 转 planner 重规划换思路")
                            cat = tool or "none"
                            verbose = cat not in seen
                            self._log("loop_break", step=step, tool=tool, n=loop["n"])
                            ctx.push_exchange(thought, None, None, self._break_hint(cat, tool, args, ctx, verbose))
                            if verbose:              # 仅首次断环续 stuck 计时,重复无视则不再续命
                                seen.add(cat)
                                self._progress["last"] = time.time()
                            continue                 # 跳过 _dispatch
                    if kind in ("action", "final"):
                        bad_parse = 0                 # 成功决策 → 清零无动作计数
                    if kind == "final":
                        # 反假阳性①:flag 必须在某工具输出里真实出现过(否则疑似编造)
                        inner = (flag[flag.find("{") + 1:flag.rfind("}")]
                                 if "{" in flag and "}" in flag else flag)
                        grounded = (bool(flag) and (store.contains(self.run_id, flag)
                                    or (len(inner) >= 4 and store.contains(self.run_id, inner))))
                        # 反假阳性②:executor 自己都说"不知道/不确定/猜的"就别放行(4232教训:thought 明说"我不知道
                        # name/email"却提交自造 hash,而它自己 run_python print 过该 hash → grounded 也满足 → 假 done)
                        _unsure = re.search(r"不知道|不确定|可能不对|可能错|也许是|瞎猜|靠猜|随便试|not sure|just a guess|guessing",
                                            thought or "", re.I)
                        if not grounded:
                            self._log("final_rejected", step=step, flag=flag, reason="未在工具输出中出现,疑似编造")
                            ctx.push_exchange(thought, "submit_flag", {"flag": flag},
                                "拒绝该 flag:它没有在任何工具输出里出现过——不要凭感觉编造!"
                                "必须用 run_python 真正算出并 print 出 flag(建议正向重算比对密文自验),确认后再 submit_flag。")
                            continue
                        if _unsure:
                            self._log("final_rejected", step=step, flag=flag, reason=f"thought含不确定措辞'{_unsure.group()}'")
                            ctx.push_exchange(thought, "submit_flag", {"flag": flag},
                                f"暂不提交:你自己的说明里带『{_unsure.group()}』这种不确定措辞。构造/哈希类 flag 必须有确定依据"
                                "(正向重算==二进制里的密文,或程序实跑走通成功分支)。先做这步验证、确认无误再 submit_flag;"
                                "若缺关键输入(如题面给的 name/email 等),说明当前无法唯一确定、别拿猜的值硬提交。")
                            continue
                        # —— D1 验证硬门:只拦 hash/构造类(内层纯十六进制且≥16),必须有二进制验证,防自证假done(4232) ——
                        _in = flag[flag.find("{") + 1:flag.rfind("}")] if "{" in flag and "}" in flag else flag
                        is_hashy = len(_in) >= 16 and all(c in "0123456789abcdefABCDEF" for c in _in)
                        binv = (flag in self.state.get("verified", set())
                                or (store.contains(self.run_id, "VERIFY_OK") and store.contains(self.run_id, flag)))
                        if is_hashy and not binv:
                            self._log("final_rejected", step=step, flag=flag, reason="hash类未过二进制验证硬门")
                            ctx.push_exchange(thought, "submit_flag", {"flag": flag},
                                "暂不提交:这是 hash/构造类 flag(内层纯十六进制),必须证明【正向重算==从二进制独立取出的目标】:"
                                "run_python 里独立取目标值、正向重算、assert 相等后 print('VERIFY_OK', flag);**禁自证**。"
                                "或 solve_verify/docker_run 实跑验。若 flag=hash(未知输入)且题面没给输入→ report_unsolved 诚实退出。")
                            continue
                        self._log("flag_found", step=step, flag=flag)
                        return {"flag": flag, "steps": step, "state": self.state,
                                "trace": ctx.step_notes, "ledger": ctx.ledger_text()}
                    if kind == "unsolved":     # D2:诚实退出(二进制无密文可对),不逼造假
                        self._log("unsolved", step=step, reason=args.get("reason"), candidate=args.get("candidate"))
                        return {"flag": None, "solved": False, "candidate": args.get("candidate"),
                                "reason": args.get("reason"), "steps": step, "state": self.state,
                                "trace": ctx.step_notes, "ledger": ctx.ledger_text(),
                                "decompiles": ctx.decompile_dump(), "summary": self._summarize_round(ctx)}
                    if kind == "action":
                        obs = self._dispatch(tool, args, store)
                        self._log("tool_result", step=step, tool=tool, args=args, obs=obs)
                        pre = (len(ctx.func_map), len(ctx.reads), len(ctx.scans))  # 台账快照
                        obs_txt = ctx.record(step, tool, args, obs, thought)
                        obs_txt += knowledge.inject(tool, args, obs, seen_kb)  # 触发式即时注入知识(如花指令→改模拟)
                        grew = (len(ctx.func_map), len(ctx.reads), len(ctx.scans)) != pre  # 台账长出新东西=学到新信息
                        # 新进展检测(§11):学到新信息(反编译新函数/读新字节/首次定位关键函数)或解题输出 → 重置stuck计时。
                        if grew or _is_progress(tool, obs):
                            self._progress["last"] = time.time()
                        # 连续纯探索护栏:反复反编译/读字节不动手(grew 会骗过 stuck 早停)→ 强推按判型执行工作流(治 3521/1886/6600 反复反编译瞎逛)
                        _EXPLORE = {"ida_decompile", "ida_disasm", "ida_read_bytes",
                                    "ida_list_functions", "find_key_functions", "recall"}
                        self._progress["explore_n"] = (self._progress.get("explore_n", 0) + 1) if tool in _EXPLORE else 0
                        if self._progress["explore_n"] >= 10 and "explore_glut" not in seen_kb:
                            seen_kb.add("explore_glut")
                            obs_txt += ("\n\n**⚠ 已连续 10+ 步只在反编译/读字节、没动手解题**(反复反编译新函数会骗过早停但零进展)。"
                                        "**停下,按判型执行对应工作流**:VM→dump 字节码数组+写 Python 解释器(拿不准的 handler 用 emulate_function 观测);"
                                        "SMC/魔改→emulate_function 从解密函数跑起再 read_bytes 取运行时值(别信静态);"
                                        "算法读懂了→run_python 写逆运算;构造型 flag(md5()/+)→自己按公式算各部分再拼。别再反编译更多函数。")
                        # 原生往返入窗口:thought=content, tool/args → 回放为 assistant.tool_calls + role:tool
                        ctx.push_exchange(thought, tool, args, obs_txt)
                    else:   # kind == "none":模型没调任何工具 → 提示去调工具
                        bad_parse += 1
                        hint = ("你上一步没有调用任何工具。请**直接调用相应工具**推进解题(别只在正文里空谈);"
                                "确信拿到 flag 时调用 submit_flag 提交。")
                        ctx.push_exchange(thought, None, None, hint)
                except Exception as e:      # 未捕获异常 → 记录并继续下一步,绝不崩整题(§11)
                    self._log("step_error", step=step, error=repr(e))
                    continue
            return self._fail(ctx, self.max_steps, "达到步数上限")
        finally:
            store.close()
            self._close_ida()
