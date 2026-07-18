"""摸清本地 thinking 模型行为:content vs reasoning 字段、能否关思考、延迟/token 账。

决定 §3.3 Executor 该关思考、以及自研 ReAct 该读哪个字段。
"""
import json
import time

import requests

from antirev import config

BASE = config.MODEL_BASE_URL.rstrip("/")
MODEL = config.MODEL_NAME


def call(label, messages, extra=None, max_tokens=1500, timeout=600):
    body = {"model": MODEL, "messages": messages, "max_tokens": max_tokens, "temperature": 0}
    if extra:
        body.update(extra)
    t = time.time()
    try:
        r = requests.post(BASE + "/chat/completions", json=body, timeout=timeout)
        dt = time.time() - t
        j = r.json()
    except Exception as e:
        print(f"--- {label}: EXC {e!r}")
        return
    msg = j["choices"][0]["message"] if j.get("choices") else {}
    fr = j["choices"][0].get("finish_reason") if j.get("choices") else "?"
    print(f"--- {label}: {dt:.1f}s finish={fr} usage={j.get('usage', {})}")
    print("  msg keys:", list(msg.keys()))
    rsn = msg.get("reasoning") or ""
    print(f"  reasoning len={len(rsn)} head={rsn[:120]!r}")
    print(f"  content={msg.get('content')!r}"[:400])


def main():
    print(f"endpoint={BASE} model={MODEL}")
    call("A default(thinking?)", [{"role": "user", "content": "What is 40+2? Give the number only."}])
    call("B /no_think", [{"role": "user", "content": "What is 40+2? Give the number only. /no_think"}])
    call("C enable_thinking=false",
         [{"role": "user", "content": "What is 40+2? Give the number only."}],
         extra={"chat_template_kwargs": {"enable_thinking": False}})


if __name__ == "__main__":
    main()
