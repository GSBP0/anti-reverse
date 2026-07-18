"""探测本地模型端点:基础生成 + 延迟 + 是否支持 OpenAI function-calling(tools/tool_calls)。

用于 §14 step 0 / Task 11:决定 Executor 走 create_react_agent(原生 tool call)还是显式 ReAct 文本协议。
"""
import json
import time

import requests

from antirev import config

BASE = config.MODEL_BASE_URL.rstrip("/")
MODEL = config.MODEL_NAME


def chat(messages, tools=None, max_tokens=64, timeout=600):
    body = {"model": MODEL, "messages": messages, "max_tokens": max_tokens, "temperature": 0}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    t = time.time()
    r = requests.post(BASE + "/chat/completions", json=body, timeout=timeout)
    dt = time.time() - t
    try:
        return dt, r.status_code, r.json()
    except Exception:
        return dt, r.status_code, r.text


def main():
    print(f"endpoint={BASE} model={MODEL}")
    print("=== 1. 基础生成(含首次冷加载) ===")
    dt, sc, resp = chat([{"role": "user", "content": "Reply with exactly: PONG"}], max_tokens=16)
    print(f"status={sc} latency={dt:.1f}s")
    print("resp:", json.dumps(resp, ensure_ascii=False)[:400])

    print("=== 2. function-calling 支持 ===")
    tools = [{"type": "function", "function": {
        "name": "add", "description": "add two integers",
        "parameters": {"type": "object",
                       "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                       "required": ["a", "b"]}}}]
    dt, sc, resp = chat([{"role": "user", "content": "Use the add tool to compute 40 + 2."}],
                        tools=tools, max_tokens=200)
    print(f"status={sc} latency={dt:.1f}s")
    msg = resp["choices"][0]["message"] if isinstance(resp, dict) and resp.get("choices") else {}
    print("tool_calls present:", bool(msg.get("tool_calls")))
    print("message:", json.dumps(msg, ensure_ascii=False)[:700])


if __name__ == "__main__":
    main()
