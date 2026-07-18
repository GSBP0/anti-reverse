"""自研 ReAct 文本协议 Executor(§12)——针对本地端点(mlx_lm.server)实测特性:

- 端点**不支持原生 tool_calls**(把工具调用当文本返回),故用显式文本协议 + 严格解析 + 纠错重试。
- 模型是 thinking 模型;用 chat_template_kwargs.enable_thinking=false **关思考**(§3.3),实测省 ~16x 延迟。
- 步数不设过紧上限(信任模型自纠);工具/解析出错回喂让模型改。

协议:每步模型输出(可含一行 THOUGHT,会被忽略)
    ACTION: {"tool":"<名>","args":{...}}          # 调用工具
  或(拿到真 flag 后)
    FINAL: <flag>
Executor 解析 ACTION → 执行 → 追加 OBSERVATION,循环至 FINAL 或步数上限。

两条通用解题路线(不针对单题):
  (A) 读懂算法→写逆运算:ida_decompile 读逻辑 → 若可逆(异或/编码/TEA/XTEA/RC4/移位…),
      ida_read_bytes 取密文/密钥常量 → run_python 写逆运算脚本(内含正向重算自验)算出 flag。
  (B) 符号执行:若是"读输入→比较到达成功分支"型,solve_locate → solve_angr → solve_verify。
"""
from __future__ import annotations
import json
import re

import requests

from antirev import config
from antirev.memory.store import MemoryStore
from antirev.memory.context import ContextManager
from antirev.tools.ida_tools import IdaSession
from antirev.tools.solve_locate import locate_targets
from antirev.tools.solve_angr import solve_angr as _run_angr
from antirev.tools.solve_verify import verify_candidate
from antirev.tools.terminal import terminal as _run_terminal
from antirev.tools.run_code import run_python as _run_python

TOOL_SPEC = """可用工具(每步只调一个):
- ida_list_functions args:{"filter":"可选子串"}          列出函数(名+地址)。找不到某函数名时用它定位!
- ida_decompile   args:{"name_or_addr":"main|0x.."}      反编译一个函数。返回 pseudocode + data_refs(引用的数据真实地址)
                                                         + callees(调用的函数名+地址)。顺 callees 逐层深入(如 main→check_flag)
- ida_read_bytes  args:{"name_or_addr":"0x..","size":N}  读密文/密钥等原始字节(返回 hex)。**按 data_refs 给的真实地址读,别用伪代码显示名**
- run_python      args:{"code":"<python>"}                跑你写的解题脚本(有 pwntools/z3;变量 BINARY 是题目路径)
- solve_locate    args:{}                                确定性定位成功/失败分支地址
- solve_angr      args:{"stdin_len":N}                    符号执行求输入(自动用已定位 find/avoid)
- solve_verify    args:{}                                把上一步 angr 候选喂回二进制自验
- terminal        args:{"command":"..."}                 杂项命令(注:python 是系统解释器,无 ida 模块)
- recall          args:{"artifact_id":N}                 重看某步观察的全文(早前步骤只留摘要,需要时按 artifact#N 取回)"""

SYSTEM_PROMPT = f"""你是逆向 Executor,目标是解出 flag。按题选两条通用路线之一:
(A) 读懂算法→写逆运算:先 ida_decompile 读 main/校验逻辑。若是可逆算法(异或/base64/移位/TEA/XTEA/RC4…),
    用 ida_read_bytes 取出密文/密钥常量,再 run_python 写逆运算脚本算 flag —— 脚本里最好正向重算一遍自验,并 print(flag)。
(B) 符号执行:若是"读输入→逐步比较→到达成功分支"型,solve_locate → solve_angr(stdin_len=?) → solve_verify。

每步只输出下面之一(可先写一行 THOUGHT: 简述):
ACTION: {{"tool":"<名>","args":{{...}}}}
FINAL: <flag>

{TOOL_SPEC}

拿到确信的 flag(如 NSSCTF{{...}} / flag{{...}})后输出 FINAL。工具报错或结果不对就换方法/改参数重试,不要放弃。"""

_FUNC_RE = re.compile(r"<function=(\w+)>\s*(\{.*?\})\s*</function>", re.S)
_FINAL_RE = re.compile(r"FINAL:\s*(\S.*)")


def _extract_json(s: str):
    start = s.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return s[start:i + 1]
    return None


def parse_step(text: str):
    """返回 ('action',{tool,args}) / ('final',flag) / (None,None)。ACTION 优先。"""
    if "ACTION:" in text:
        js = _extract_json(text.split("ACTION:", 1)[1])
        if js:
            try:
                obj = json.loads(js)
                tool = obj.get("tool") or obj.get("name")
                if tool:
                    return "action", {"tool": tool, "args": obj.get("args") or obj.get("arguments") or {}}
            except Exception:
                pass
    mf = _FUNC_RE.search(text)
    if mf:
        try:
            return "action", {"tool": mf.group(1), "args": json.loads(mf.group(2))}
        except Exception:
            pass
    mfin = _FINAL_RE.search(text)
    if mfin:
        return "final", mfin.group(1).strip().strip("`").strip()
    return None, None


class ChatClient:
    def __init__(self, base_url=None, model=None, think=False):
        self.base = (base_url or config.MODEL_BASE_URL).rstrip("/")
        self.model = model or config.MODEL_NAME
        self.think = think

    def complete(self, messages, max_tokens=800, temperature=0.0, timeout=180):
        body = {"model": self.model, "messages": messages,
                "max_tokens": max_tokens, "temperature": temperature}
        if not self.think:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        r = requests.post(self.base + "/chat/completions", json=body, timeout=timeout)
        msg = r.json()["choices"][0]["message"]
        return msg.get("content") or msg.get("reasoning") or ""


class ReactExecutor:
    def __init__(self, binary, client=None, logger=None, max_steps=60, window=6, db_path=None):
        self.binary = binary
        self.client = client or ChatClient()
        self.logger = logger
        self.max_steps = max_steps
        self.window = window
        self.run_id = getattr(logger, "run_id", None) or "exec"
        self.db_path = db_path or ":memory:"
        self.state = {"find": None, "avoid": None, "candidate": None, "func_hint": None}

    def _log(self, type, **f):
        if self.logger:
            self.logger.event(type, **f)

    def _dispatch(self, tool, args, store):
        try:
            if tool == "recall":
                art = store.get_artifact(int(args.get("artifact_id")))
                return {"full": art["full_text"][:6000]} if art else {"error": "无此 artifact"}
            # 只读 IDA 工具:命中缓存直接返回,避免重复分析(§6.3)
            if tool in ("ida_list_functions", "ida_decompile", "ida_read_bytes"):
                cached = store.find_cached(self.run_id, tool, args)
                if cached:
                    return json.loads(cached["full_text"])
            if tool == "ida_list_functions":
                with IdaSession(self.binary) as ida:
                    fns = ida.list_functions(args.get("filter"))
                    return {"count": len(fns),
                            "functions": [{"addr": hex(f["addr"]), "name": f["name"],
                                           "size": f["size"]} for f in fns[:500]]}
            if tool == "ida_decompile":
                with IdaSession(self.binary) as ida:
                    r = ida.decompile(args["name_or_addr"])
                    return {"pseudocode": r["pseudocode"][:5000],
                            "data_refs": r.get("data_refs", []),
                            "callees": r.get("callees", [])}
            if tool == "ida_read_bytes":
                with IdaSession(self.binary) as ida:
                    return ida.get_bytes(args["name_or_addr"], int(args["size"]))
            if tool == "run_python":
                return _run_python(args["code"], binary=self.binary)
            if tool == "solve_locate":
                r = locate_targets(self.binary)
                self.state.update(find=r["find"], avoid=r["avoid"], func_hint=r.get("func_hint"))
                return {"find": r["find"], "avoid": r["avoid"]}
            if tool == "solve_angr":
                find = args.get("find") or self.state["find"]
                if not find:
                    return {"error": "请先 solve_locate 得到 find/avoid"}
                r = _run_angr(self.binary, find=find, avoid=args.get("avoid") or self.state["avoid"] or [],
                              stdin_len=int(args.get("stdin_len", 32)), start_addr=self.state.get("func_hint"))
                if r.get("found"):
                    self.state["candidate"] = r["stdin"].split("\x00")[0].strip()
                return r
            if tool == "solve_verify":
                cand = args.get("candidate") or self.state["candidate"]
                if not cand:
                    return {"error": "无候选,请先 solve_angr"}
                find, avoid = self.state["find"], self.state["avoid"]
                r = verify_candidate(self.binary, cand, find=(find[0] if find else None),
                                     avoid=(avoid[0] if avoid else None))
                r["candidate"] = cand
                return r
            if tool == "terminal":
                return _run_terminal(args.get("command", ""))
            return {"error": f"unknown tool {tool}"}
        except Exception as e:
            return {"error": repr(e)}

    def run(self, plan: str):
        store = MemoryStore(self.db_path)
        ctx = ContextManager(store, self.run_id, window=self.window)
        ctx.set_goal(plan[:200])
        last_sig, repeat, last_tool, tool_run = None, 0, None, 0
        try:
            for step in range(1, self.max_steps + 1):
                messages = ctx.build_messages(SYSTEM_PROMPT, plan)  # 有界:system+WM+最近window步
                text = self.client.complete(messages)
                self._log("executor_output", step=step, text=text[:800], ctx_msgs=len(messages))
                kind, payload = parse_step(text)
                if kind == "final":
                    self._log("flag_found", step=step, flag=payload)
                    return {"flag": payload, "steps": step, "state": self.state}
                if kind == "action":
                    tool, args = payload["tool"], payload["args"]
                    sig = json.dumps(payload, sort_keys=True, ensure_ascii=False)
                    repeat = repeat + 1 if sig == last_sig else 0
                    last_sig = sig
                    tool_run = tool_run + 1 if tool == last_tool else 0
                    last_tool = tool
                    obs = self._dispatch(tool, args, store)
                    self._log("tool_result", step=step, tool=tool, args=args, obs=obs)
                    obs_txt = ctx.record(step, tool, args, obs)  # 压缩+存全量,返回上下文视图
                    if repeat >= 2 or tool_run >= 4:  # 无进展检测(§3.4/§11)
                        self._log("no_progress", step=step, tool=tool)
                        obs_txt += ("\n\n[系统提示] 你在无进展地重复。停!换完全不同的思路:"
                                    "找不到函数就 ida_list_functions 列全部按名定位;"
                                    "读数据按 data_refs 真实地址(别用显示名);"
                                    "读懂算法后 run_python 写逆运算;或试 solve_angr。别再瞎猜地址。")
                        repeat, tool_run = 0, 0
                    ctx.push_exchange(text, obs_txt)
                else:
                    ctx.push_exchange(text, "格式错误。请只输出一行 ACTION: {json} 或 FINAL: <flag>。")
            return {"flag": None, "steps": self.max_steps, "error": "达到步数上限", "state": self.state}
        finally:
            store.close()
