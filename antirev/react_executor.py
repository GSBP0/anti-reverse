"""自研 ReAct 文本协议 Executor(§12)——针对本地端点实测特性:

- 端点**不支持原生 tool_calls**(只把工具调用当文本返回),故用显式文本协议 + 严格解析 + 纠错重试。
- 模型是 thinking 模型;用 chat_template_kwargs.enable_thinking=false **关思考**(§3.3),实测省 ~16x 延迟。
- 厚工具把 find/avoid/candidate 存会话状态,模型无需在 args 里搬运大整数地址,大幅降低编排负担(§12)。

协议:每步模型输出(可含一行 THOUGHT,会被忽略)
    ACTION: {"tool":"<名>","args":{...}}          # 调用工具
  或(拿到经 solve_verify 确认 accepted=true 的真 flag 后)
    FINAL: <flag>
Executor 解析 ACTION → 执行 → 追加 OBSERVATION,循环至 FINAL 或步数上限。
"""
from __future__ import annotations
import json
import re

import requests

from antirev import config
from antirev.tools.ida_tools import IdaSession
from antirev.tools.solve_locate import locate_targets
from antirev.tools.solve_angr import solve_angr as _run_angr
from antirev.tools.solve_verify import verify_candidate
from antirev.tools.terminal import terminal as _run_terminal

TOOL_SPEC = """可用工具(每步只调一个):
- solve_locate    args:{}                          确定性定位成功/失败分支地址,返回 find/avoid
- solve_angr      args:{"stdin_len":<int>}          符号执行求候选输入(自动用已定位的 find/avoid),返回 found/stdin
- solve_verify    args:{}                           把上一步候选喂回二进制自验,返回 accepted
- ida_decompile   args:{"name_or_addr":"main|0x.."} 反编译一个函数看逻辑
- terminal        args:{"command":"..."}            杂项命令,仅兜底"""

SYSTEM_PROMPT = f"""你是逆向 Executor。严格按 Plan,只用工具解出 flag。
每步只输出下面之一(可先写一行 THOUGHT: 简述,但必须紧跟 ACTION 或 FINAL):
ACTION: {{"tool":"<名>","args":{{...}}}}
FINAL: <flag>

{TOOL_SPEC}

只有 solve_verify 返回 accepted=true 才算真 flag,然后输出 FINAL。
典型流程:solve_locate → solve_angr(stdin_len=N) → solve_verify → FINAL。"""

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

    def complete(self, messages, max_tokens=400, temperature=0.0, timeout=180):
        body = {"model": self.model, "messages": messages,
                "max_tokens": max_tokens, "temperature": temperature}
        if not self.think:
            body["chat_template_kwargs"] = {"enable_thinking": False}
        r = requests.post(self.base + "/chat/completions", json=body, timeout=timeout)
        msg = r.json()["choices"][0]["message"]
        return msg.get("content") or msg.get("reasoning") or ""


class ReactExecutor:
    def __init__(self, binary, client=None, logger=None, max_steps=12):
        self.binary = binary
        self.client = client or ChatClient()
        self.logger = logger
        self.max_steps = max_steps
        self.state = {"find": None, "avoid": None, "candidate": None}

    def _log(self, type, **f):
        if self.logger:
            self.logger.event(type, **f)

    def _dispatch(self, tool, args):
        try:
            if tool == "solve_locate":
                r = locate_targets(self.binary)
                self.state["find"], self.state["avoid"] = r["find"], r["avoid"]
                return {"find": r["find"], "avoid": r["avoid"]}
            if tool == "solve_angr":
                find = args.get("find") or self.state["find"]
                avoid = args.get("avoid") or self.state["avoid"] or []
                if not find:
                    return {"error": "请先调用 solve_locate 得到 find/avoid"}
                r = _run_angr(self.binary, find=find, avoid=avoid,
                              stdin_len=int(args.get("stdin_len", 32)))
                if r.get("found"):
                    self.state["candidate"] = r["stdin"].split("\x00")[0].strip()
                return r
            if tool == "solve_verify":
                cand = args.get("candidate") or self.state["candidate"]
                if not cand:
                    return {"error": "无候选,请先 solve_angr"}
                find, avoid = self.state["find"], self.state["avoid"]
                r = verify_candidate(self.binary, cand,
                                     find=(find[0] if find else None),
                                     avoid=(avoid[0] if avoid else None))
                r["candidate"] = cand
                return r
            if tool == "ida_decompile":
                with IdaSession(self.binary) as ida:
                    return {"pseudocode": ida.decompile(args["name_or_addr"])["pseudocode"][:4000]}
            if tool == "terminal":
                return _run_terminal(args.get("command", ""))
            return {"error": f"unknown tool {tool}"}
        except Exception as e:
            return {"error": repr(e)}

    def run(self, plan: str):
        messages = [{"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": plan}]
        for step in range(1, self.max_steps + 1):
            text = self.client.complete(messages)
            self._log("executor_output", step=step, text=text[:600])
            kind, payload = parse_step(text)
            if kind == "final":
                self._log("flag_found", step=step, flag=payload)
                return {"flag": payload, "steps": step, "state": self.state}
            if kind == "action":
                tool, args = payload["tool"], payload["args"]
                obs = self._dispatch(tool, args)
                self._log("tool_result", step=step, tool=tool, args=args, obs=obs)
                messages.append({"role": "assistant", "content": text})
                messages.append({"role": "user",
                                 "content": f"OBSERVATION: {json.dumps(obs, ensure_ascii=False)}"})
            else:
                messages.append({"role": "assistant", "content": text})
                messages.append({"role": "user",
                                 "content": "格式错误。请只输出一行 ACTION: {json} 或 FINAL: <flag>。"})
        return {"flag": None, "steps": self.max_steps, "error": "达到步数上限", "state": self.state}
