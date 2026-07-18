"""单步端到端延迟实测(§7.4):模型调用(关/开思考、不同上下文规模)+ 各厚工具耗时。
反推 §11 的 20min/题预算下每题步数上限。结果供 docs/measurements.md。
"""
import time

import requests

from antirev import config
from antirev.tools.solve_locate import locate_targets
from antirev.tools.solve_angr import solve_angr
from antirev.tools.solve_verify import verify_candidate

BASE = config.MODEL_BASE_URL.rstrip("/")
MODEL = config.MODEL_NAME
SAMPLE = str(config.PROJECT_ROOT / "tests/samples/flagcheck")


def model_call(msgs, think, max_tokens=200):
    body = {"model": MODEL, "messages": msgs, "max_tokens": max_tokens, "temperature": 0}
    if not think:
        body["chat_template_kwargs"] = {"enable_thinking": False}
    t = time.time()
    r = requests.post(BASE + "/chat/completions", json=body, timeout=300)
    dt = time.time() - t
    j = r.json()
    return dt, j.get("usage", {})


def bench(label, fn, *a, **k):
    t = time.time()
    out = fn(*a, **k)
    dt = time.time() - t
    print(f"{label:32s} {dt:6.1f}s")
    return dt, out


def main():
    print(f"# 延迟实测 endpoint={BASE} model={MODEL}\n")
    small = [{"role": "user", "content": "输出一行 ACTION: {\"tool\":\"solve_locate\",\"args\":{}}"}]
    big_ctx = "OBSERVATION: " + ("反编译片段 " * 800)  # ~4k tokens 上下文
    big = [{"role": "system", "content": "你是逆向 Executor。"},
           {"role": "user", "content": big_ctx + "\n下一步输出 ACTION。"}]

    print("## 模型单步(关思考,§3.3 Executor 用)")
    dt1, u1 = model_call(small, think=False)
    print(f"  小上下文(~{u1.get('prompt_tokens','?')}tok in): {dt1:.2f}s  out={u1.get('completion_tokens','?')}tok")
    dt2, u2 = model_call(big, think=False)
    print(f"  大上下文(~{u2.get('prompt_tokens','?')}tok in): {dt2:.2f}s  out={u2.get('completion_tokens','?')}tok")

    print("## 模型单步(开思考,对比)")
    dt3, u3 = model_call(small, think=True)
    print(f"  小上下文: {dt3:.2f}s  out={u3.get('completion_tokens','?')}tok (含思考)")

    print("\n## 厚工具耗时(单次)")
    _, tgt = bench("solve_locate", locate_targets, SAMPLE)
    bench("solve_angr", solve_angr, SAMPLE, tgt["find"], tgt["avoid"], "stdin", 17)
    bench("solve_verify", verify_candidate, SAMPLE, "flag{unic0rn_x0r}",
          find=tgt["find"][0], avoid=tgt["avoid"][0])

    print("\n## 结论")
    step = dt1 + 8  # 模型(关思考) + 典型工具
    print(f"典型单步 ≈ 模型{dt1:.1f}s + 工具~8s = {step:.0f}s → 20min/题 ≈ {int(1200/step)} 步")


if __name__ == "__main__":
    main()
