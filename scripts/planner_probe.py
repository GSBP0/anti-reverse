"""用 2000 真实全量反编译+台账,验证修复后 planner 读全量:不崩、出 plan、plan≤10k。"""
import os
os.environ["TPS_METRICS_PATH"] = "logs/ptest_tps.jsonl"
import time
import requests
from antirev.memory.store import MemoryStore
from antirev.memory.context import ContextManager
from antirev.react_executor import ChatClient
from antirev.graph.nodes import PLANNER_SYS

st = MemoryStore("logs/eval_r7_2000.db")
ctx = ContextManager(st, "eval_r7_2000")
ctx.load_prior(st)
ledger = ctx.ledger_text()
decompiles = ctx.decompile_dump()
st.close()

parts = ["## 预分析\n2000 funnyre x86-64 ELF stripped 花指令",
         "\n## 第1次重规划:上一轮(10步)未解出。",
         f"\n### 工具调用持久台账:\n{ledger}",
         f"\n### 上一轮所有反编译/反汇编全文:\n{decompiles}",
         "\n据此判断题型并产出 Plan(Plan正文精炼,控制在1万字符内)。"]
user_msg = "\n".join(parts)
est = (len(PLANNER_SYS) + len(user_msg)) // 3
plan_max = max(2000, min(8000, 60000 - est))
print(f"est_prompt~{est}token plan_max={plan_max} 预期总量={est + plan_max}", flush=True)

c = ChatClient(think=True, temperature=0.4)
t0 = time.time()
plan = c.complete([{"role": "system", "content": PLANNER_SYS},
                   {"role": "user", "content": user_msg}], max_tokens=plan_max, timeout=600, retries=1)
dt = time.time() - t0
print(f"用时{dt:.0f}s plan长度={len(plan)}字符 {'非空OK-读全量不崩' if plan.strip() else '空-仍失败'}", flush=True)
print("--- plan前600字 ---\n" + plan[:600], flush=True)
try:
    r = requests.post("http://127.0.0.1:7777/v1/chat/completions",
                      json={"model": "qwen3.6-35b-a3b-6bit", "messages": [{"role": "user", "content": "hi"}],
                            "max_tokens": 3}, timeout=20)
    print(f"\n测试后mlx存活: {r.status_code == 200}", flush=True)
except Exception as e:
    print(f"\n测试后mlx崩了: {repr(e)[:80]}", flush=True)
print("DONE", flush=True)
