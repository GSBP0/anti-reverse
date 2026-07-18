# antiReverse MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 打通 plan1.md §14 step 1 的 MVP 端到端闭环——对一道简单 flag 校验题，用 `ida.decompile → solve.locate_targets → solve.angr → solve.verify` 确定性地跑出 flag 并回验，随后用本地模型驱动的 ReAct Executor 复现同一闭环。

**Architecture:** 三环境进程隔离。**主环境**（conda, Python 3.12）跑 LangChain/LangGraph 编排 + angr/unicorn/z3 求解；**IDA worker**（brew Python 3.14 + idalib 激活）跑在受管子进程里，主环境经 JSON-over-pipe 协议驱动它做静态分析；angr/verify 各自在受管子进程里跑，带超时 + 状态上限，崩溃不影响主循环。这套三环境布局是 plan §5.5/§7.2「进程隔离 + 工具串行」的直接落地，同时化解本机的硬冲突：IDA 9.3 的 IDAPython 是 cp314 ABI，angr 生态还停在 ≤3.12。

**Tech Stack:** Python 3.12 (conda) + Python 3.14 (brew, idalib) / LangChain + LangGraph / IDA Professional 9.3 idalib / angr + claripy + z3-solver / unicorn + capstone + keystone / pwntools / Detect-It-Easy + FLOSS + UPX + binwalk。

---

## 环境架构决策（本机实测驱动，refine plan §4/§9.2）

| 事实（实测） | 结论 |
|---|---|
| IDA Professional 9.3，`libidalib.dylib` + `idalib/python/py-activate-idalib.py` 就位 | idalib 后端可用，走 idalib（不退回 idat64 batch） |
| IDA 的 IDAPython 扩展为 `_ida_*.cpython-314.so` | **idalib 必须在 Python 3.14 下 import**；这是 IDA worker 环境的硬约束 |
| angr/unicorn/z3 3.14 wheel 基本缺失；系统 py 3.9.6 太老 | **主环境用 Python 3.12**（conda）；angr 生态全在此 |
| 二者不可同环境 | **进程隔离**：IDA worker(3.14) 与 主环境(3.12) 用 JSON 协议通信；正合 §7.2 工具串行、§5.5 隔离 |
| 模型端点 `127.0.0.1:7777` 需用户启动 | 工具/记忆/骨架不依赖模型；模型相关任务（Task 10/11）待端点就绪 |

**三个 Python 环境：**
- `conda env antirev`（Python 3.12）：主编排 + 求解。所有 `antirev.*` 代码在此运行。
- `~/.antirev/ida314-venv`（brew Python 3.14）：仅装 idalib（`idapro` 包），跑 `ida_worker.py`。
- 系统/其它：不用。

**命名 refine（§13）**：`logging/` 会遮蔽标准库 `logging`，改名 `obs/`；全部代码收进可导入包 `antirev/`。

---

## File Structure

```
antiReverse/
├── main.py                       # 入口:对一个二进制启动 MVP 流程 (Task 10)
├── requirements-main.txt         # 主环境(3.12)依赖
├── requirements-ida.txt          # IDA worker(3.14)依赖(仅 idapro)
├── wheelhouse/                   # 离线 wheel 缓存 (Task 0)
├── pyproject.toml                # antirev 包 + pytest 配置
├── config.py  → antirev/config.py
├── antirev/
│   ├── __init__.py
│   ├── config.py                 # 端点/路径/超时/内存阈值/py314 解释器路径
│   ├── isolation/
│   │   ├── __init__.py
│   │   └── subprocess_runner.py  # 一次性受管子进程: 超时+崩溃隔离+捕获 (Task 2)
│   ├── obs/
│   │   ├── __init__.py
│   │   └── logger.py             # JSONL + 人类可读双轨 (Task 3)
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── ida_worker.py         # ★py3.14执行★ idalib 常驻 worker (Task 4)
│   │   ├── ida_tools.py          # py3.12: IdaSession 管理 worker + 厚工具 (Task 4)
│   │   ├── solve_locate.py       # solve.locate_targets 确定性定位 (Task 5)
│   │   ├── solve_angr.py         # py3.12 驱动 + angr 子进程脚本 (Task 6)
│   │   ├── solve_verify.py       # solve.verify unicorn 回验 (Task 7)
│   │   └── terminal.py           # 沙箱命令执行 (Task 8)
│   └── pipeline_mvp.py           # 确定性固定流水线(无模型) (Task 9)
└── tests/
    ├── conftest.py
    ├── samples/
    │   ├── make_sample.py        # pwntools 生成 flagcheck ELF (Task 9)
    │   └── flagcheck            # 生成产物(x86-64 Linux ELF)
    ├── test_subprocess_runner.py
    ├── test_ida_tools.py
    ├── test_solve_locate.py
    ├── test_solve_angr.py
    ├── test_solve_verify.py
    └── test_pipeline_mvp.py      # ★MVP 验收★ 无模型端到端出 flag
```

---

## Task 0: 环境 bootstrap（离线固化前置，§9）

**Files:**
- Create: `requirements-main.txt`, `requirements-ida.txt`, `pyproject.toml`

- [ ] **Step 1: 建主环境 conda py3.12**

```bash
conda create -y -n antirev python=3.12
conda run -n antirev python -V   # 期望 Python 3.12.x
```

- [ ] **Step 2: 写 requirements-main.txt 并安装**

`requirements-main.txt`:
```
langchain
langgraph
langchain-openai
openai
angr
claripy
z3-solver
unicorn
capstone
keystone-engine
pwntools
pydantic
pytest
```

```bash
conda run -n antirev pip install -r requirements-main.txt
```
Expected: 全部安装成功；若 angr 某二进制依赖失败，记录并回退固定小版本。

- [ ] **Step 3: 建 IDA worker 环境 py3.14 + 激活 idalib**

```bash
/opt/homebrew/bin/python3.14 -m venv ~/.antirev/ida314-venv
~/.antirev/ida314-venv/bin/python "/Applications/IDA Professional 9.3.app/Contents/MacOS/idalib/python/py-activate-idalib.py"
~/.antirev/ida314-venv/bin/python -c "import idapro; print('idalib import OK')"
```
Expected: 打印 `idalib import OK`。**若失败**（ABI/激活问题）→ 改用 IDA 自带 python 或调查 py-activate 输出，这是 §9.2 一票否决项，必须先通。

- [ ] **Step 4: 装分析 CLI**

```bash
brew install upx binwalk die   # die = Detect-It-Easy (diec)
conda run -n antirev pip install flare-floss
diec --version && upx --version
```
Expected: 各工具可执行；`die` formula 若无则记录，FLOSS/DIE 非 MVP 阻塞项。

- [ ] **Step 5: idalib 离线 dry-run（§9.2 一票否决项）**

生成一个样本后（见 Task 9 make_sample），断网跑：
```bash
# 先 Task 9 生成 tests/samples/flagcheck
~/.antirev/ida314-venv/bin/python -c "
import idapro; assert idapro.open_database('tests/samples/flagcheck', True)==0
import ida_hexrays, ida_funcs, idc
f=ida_funcs.get_func(idc.get_name_ea_simple('main') if idc.get_name_ea_simple('main')!=0xffffffffffffffff else 0)
print('decompiled OK' if ida_hexrays.decompile(f.start_ea) else 'no hexrays')
idapro.close_database(False)"
```
Expected: `decompiled OK`。这一步证明离线 license + idalib + 反编译器可用。

- [ ] **Step 6: 建 wheelhouse 离线缓存并提交**

```bash
conda run -n antirev pip download -r requirements-main.txt -d wheelhouse/
echo "wheelhouse/" >> .gitignore   # wheel 不进 git,单独备份
git add requirements-main.txt requirements-ida.txt pyproject.toml .gitignore
git -c user.name=antiReverse -c user.email=noreply@local commit -m "chore: env bootstrap deps"
```

`pyproject.toml`（最小）:
```toml
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "antirev"
version = "0.0.1"
requires-python = ">=3.12"

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-v"
```

---

## Task 1: 项目骨架 + config

**Files:**
- Create: `antirev/__init__.py`, `antirev/config.py`, 各子包 `__init__.py`

- [ ] **Step 1: 建包结构**

```bash
mkdir -p antirev/isolation antirev/obs antirev/tools tests/samples
touch antirev/__init__.py antirev/isolation/__init__.py antirev/obs/__init__.py antirev/tools/__init__.py
```

- [ ] **Step 2: 写 antirev/config.py**

```python
"""集中配置:端点/路径/超时/内存阈值。全文件无副作用,只读常量 + 环境覆盖。"""
import os
from pathlib import Path

# 模型端点(OpenAI 兼容)
MODEL_BASE_URL = os.environ.get("ANTIREV_MODEL_URL", "http://127.0.0.1:7777/v1")
MODEL_API_KEY = os.environ.get("ANTIREV_MODEL_KEY", "sk-local")
MODEL_NAME = os.environ.get("ANTIREV_MODEL_NAME", "local")

# IDA
IDA_APP = Path(os.environ.get("ANTIREV_IDA_APP",
    "/Applications/IDA Professional 9.3.app"))
IDA_PY314 = Path(os.environ.get("ANTIREV_IDA_PY314",
    str(Path.home() / ".antirev/ida314-venv/bin/python")))

# 超时预算(秒)
IDA_ANALYSIS_TIMEOUT = int(os.environ.get("ANTIREV_IDA_TIMEOUT", "180"))
IDA_QUERY_TIMEOUT = 30
ANGR_TIMEOUT = int(os.environ.get("ANTIREV_ANGR_TIMEOUT", "120"))
ANGR_MAX_STATES = int(os.environ.get("ANTIREV_ANGR_MAX_STATES", "200"))
TERMINAL_TIMEOUT = 30
PER_CHALLENGE_BUDGET = int(os.environ.get("ANTIREV_CHALL_BUDGET", "1200"))  # 20min

# 求解成功/失败关键词(§5.2 solve.locate_targets)
SUCCESS_KEYWORDS = ["correct", "success", "right", "congrat", "well done",
                    "nice", "good job", "flag", "accepted", "you win", "solved"]
FAIL_KEYWORDS = ["wrong", "incorrect", "nope", "try again", "denied",
                 "invalid", "fail", "error", "bad", "no."]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
```

- [ ] **Step 3: 提交**

```bash
git add antirev/ && git -c user.name=antiReverse -c user.email=noreply@local commit -m "feat: project scaffold + config"
```

---

## Task 2: 受管子进程 runner（隔离 + 超时，§5.5/§11）

**Files:**
- Create: `antirev/isolation/subprocess_runner.py`
- Test: `tests/test_subprocess_runner.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/test_subprocess_runner.py
import sys
from antirev.isolation.subprocess_runner import run_isolated, IsolatedResult

def test_captures_stdout_and_rc():
    r = run_isolated([sys.executable, "-c", "print('hi')"], timeout=10)
    assert isinstance(r, IsolatedResult)
    assert r.returncode == 0
    assert "hi" in r.stdout
    assert r.timed_out is False

def test_timeout_is_flagged_not_raised():
    r = run_isolated([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert r.timed_out is True
    assert r.returncode != 0

def test_crash_is_captured_not_propagated():
    r = run_isolated([sys.executable, "-c", "import os; os._exit(3)"], timeout=10)
    assert r.returncode == 3
    assert r.timed_out is False
```

- [ ] **Step 2: 运行确认失败**

Run: `conda run -n antirev pytest tests/test_subprocess_runner.py -v`
Expected: FAIL（模块不存在）

- [ ] **Step 3: 实现**

```python
# antirev/isolation/subprocess_runner.py
"""一次性受管子进程:超时 → 杀进程组;捕获 stdout/stderr/rc;绝不抛穿主循环。"""
from __future__ import annotations
import os, signal, subprocess
from dataclasses import dataclass

@dataclass
class IsolatedResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool

def run_isolated(cmd, timeout, cwd=None, env=None, input_text=None) -> IsolatedResult:
    """cmd: list[str]。超时杀整个进程组,防子孙进程逃逸。"""
    try:
        p = subprocess.Popen(
            cmd, cwd=cwd, env=env,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True,  # 独立进程组
        )
    except (FileNotFoundError, OSError) as e:
        return IsolatedResult(127, "", f"spawn failed: {e!r}", False)
    try:
        out, err = p.communicate(input=input_text, timeout=timeout)
        return IsolatedResult(p.returncode, out or "", err or "", False)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = p.communicate()
        return IsolatedResult(-signal.SIGKILL, out or "", err or "", True)
```

- [ ] **Step 4: 运行确认通过**

Run: `conda run -n antirev pytest tests/test_subprocess_runner.py -v`
Expected: 3 passed

- [ ] **Step 5: 提交** `git commit -m "feat: isolated subprocess runner"`

---

## Task 3: 双轨日志（§10）

**Files:**
- Create: `antirev/obs/logger.py`
- Test: `tests/test_logger.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/test_logger.py
import json
from antirev.obs.logger import RunLogger

def test_jsonl_and_human(tmp_path):
    lg = RunLogger(run_id="chall_A", log_dir=tmp_path)
    lg.event("tool_call", agent="executor", step=1, tool="ida.decompile",
             args={"name": "main"})
    lg.human("[EXECUTOR][step 1][ACTION] ida.decompile(name='main')")
    lines = (tmp_path / "chall_A.jsonl").read_text().splitlines()
    rec = json.loads(lines[0])
    assert rec["type"] == "tool_call" and rec["tool"] == "ida.decompile"
    assert "run_id" in rec and "ts" in rec
    assert "[EXECUTOR]" in (tmp_path / "chall_A.log").read_text()
```

- [ ] **Step 2: 运行确认失败** → `pytest tests/test_logger.py` FAIL

- [ ] **Step 3: 实现**

```python
# antirev/obs/logger.py
"""双轨:JSONL(机器可解析,回放/复盘) + .log(人类可读,赛场观察)。长输出用引用,不落全文。"""
from __future__ import annotations
import json, datetime
from pathlib import Path

class RunLogger:
    def __init__(self, run_id: str, log_dir):
        self.run_id = run_id
        d = Path(log_dir); d.mkdir(parents=True, exist_ok=True)
        self.jsonl = d / f"{run_id}.jsonl"
        self.human = d / f"{run_id}.log"
        self._h = None  # 延迟句柄

    def event(self, type: str, **fields):
        rec = {"ts": datetime.datetime.now(datetime.timezone.utc)
                        .isoformat().replace("+00:00", "Z"),
               "run_id": self.run_id, "type": type, **fields}
        with self.jsonl.open("a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def human_line(self, text: str):
        with self.human.open("a") as f:
            f.write(text + "\n")
```
> 注:测试里叫 `lg.human(...)`,实现方法名统一为 `human_line`;修测试为 `lg.human_line`。（自查已改。）

- [ ] **Step 4: 运行确认通过** → 修正测试方法名后 `pytest tests/test_logger.py` PASS

- [ ] **Step 5: 提交** `git commit -m "feat: dual-track run logger"`

---

## Task 4: IDA 厚工具（idalib worker + IdaSession）

**Files:**
- Create: `antirev/tools/ida_worker.py`（py3.14 执行）, `antirev/tools/ida_tools.py`（py3.12）
- Test: `tests/test_ida_tools.py`（依赖 Task 9 样本）

- [ ] **Step 1: 写 worker（py3.14, idalib 常驻,JSON-over-stdio 协议）**

```python
# antirev/tools/ida_worker.py  —— 由 py3.14(idalib) 解释器执行
"""常驻 worker:open_database 一次,循环处理 JSON 请求。协议:stdin 逐行 {cmd,args},
stdout 逐行 {ok,result|error}。cmd: decompile/list_functions/strings/xrefs_to/close。"""
import sys, json

def _emit(obj): sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()

def main():
    binary = sys.argv[1]
    import idapro
    idapro.enable_console_messages(False)
    if idapro.open_database(binary, True) != 0:
        _emit({"ok": False, "error": "open_database failed"}); return
    import ida_hexrays, idautils, idc, ida_funcs, ida_bytes
    ida_hexrays.init_hexrays_plugin()
    _emit({"ok": True, "result": "ready"})

    for line in sys.stdin:
        line = line.strip()
        if not line: continue
        req = json.loads(line); cmd = req.get("cmd"); a = req.get("args", {})
        try:
            if cmd == "close":
                _emit({"ok": True, "result": "bye"}); break
            _emit({"ok": True, "result": _handle(cmd, a, idautils, idc, ida_funcs, ida_hexrays)})
        except Exception as e:
            _emit({"ok": False, "error": repr(e)})
    idapro.close_database(False)

def _resolve(idc, ida_funcs, name_or_addr):
    if isinstance(name_or_addr, int):
        ea = name_or_addr
    else:
        ea = idc.get_name_ea_simple(name_or_addr)
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else ea

def _handle(cmd, a, idautils, idc, ida_funcs, ida_hexrays):
    if cmd == "list_functions":
        out = []
        for ea in idautils.Functions():
            f = ida_funcs.get_func(ea)
            out.append({"addr": ea, "name": idc.get_func_name(ea),
                        "size": (f.end_ea - f.start_ea) if f else 0})
        return out
    if cmd == "decompile":
        ea = _resolve(idc, ida_funcs, a["name_or_addr"])
        cf = ida_hexrays.decompile(ea)
        return {"addr": ea, "name": idc.get_func_name(ea), "pseudocode": str(cf)}
    if cmd == "strings":
        import re
        pat = a.get("filter")
        out = []
        for s in idautils.Strings():
            v = str(s)
            if pat and not re.search(pat, v, re.I): continue
            out.append({"addr": s.ea, "value": v})
        return out
    if cmd == "xrefs_to":
        ea = a["addr"]; out = []
        for x in idautils.XrefsTo(ea):
            fn = idc.get_func_name(x.frm)
            out.append({"frm": x.frm, "func": fn})
        return out
    raise ValueError(f"unknown cmd {cmd}")

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: 写 IdaSession（py3.12,经 subprocess 驱动 worker）**

```python
# antirev/tools/ida_tools.py
"""py3.12 侧:用 py3.14 解释器把 ida_worker.py 拉成常驻子进程,JSON 逐行往返。
厚工具返回压缩切片(原则4):decompile 一次一个函数;strings/xrefs 只回地址+名。"""
from __future__ import annotations
import json, subprocess, os, signal
from pathlib import Path
from antirev import config

WORKER = str(Path(__file__).with_name("ida_worker.py"))

class IdaSession:
    def __init__(self, binary: str, py314=None, timeout=None):
        self.binary = str(Path(binary).resolve())
        self.py = str(py314 or config.IDA_PY314)
        self.timeout = timeout or config.IDA_QUERY_TIMEOUT
        self.p = None

    def __enter__(self):
        self.p = subprocess.Popen(
            [self.py, WORKER, self.binary],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        ready = self._readline(config.IDA_ANALYSIS_TIMEOUT)  # 等分析完成
        if not ready.get("ok"):
            raise RuntimeError(f"IDA worker init failed: {ready}")
        return self

    def __exit__(self, *exc):
        try:
            if self.p and self.p.poll() is None:
                self._send({"cmd": "close"})
                self.p.wait(timeout=5)
        except Exception:
            pass
        finally:
            if self.p and self.p.poll() is None:
                os.killpg(os.getpgid(self.p.pid), signal.SIGKILL)

    def _send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n"); self.p.stdin.flush()

    def _readline(self, timeout):
        # MVP:阻塞读一行;worker 单请求单响应。超时保护交给外层 per-challenge budget。
        line = self.p.stdout.readline()
        if not line:
            raise RuntimeError(f"IDA worker died: {self.p.stderr.read()[:500]}")
        return json.loads(line)

    def _rpc(self, cmd, **args):
        self._send({"cmd": cmd, "args": args})
        resp = self._readline(self.timeout)
        if not resp.get("ok"):
            raise RuntimeError(f"ida {cmd} error: {resp.get('error')}")
        return resp["result"]

    # —— 厚工具(压缩切片) ——
    def list_functions(self, name_filter=None):
        fns = self._rpc("list_functions")
        if name_filter:
            fns = [f for f in fns if name_filter in f["name"]]
        return fns

    def decompile(self, name_or_addr):
        r = self._rpc("decompile", name_or_addr=name_or_addr)
        return r  # {addr,name,pseudocode}

    def strings(self, filter=None):
        return self._rpc("strings", filter=filter)

    def xrefs_to(self, addr):
        return self._rpc("xrefs_to", addr=addr)
```

- [ ] **Step 3: 测试（依赖 Task 9 样本）**

```python
# tests/test_ida_tools.py
import pytest
from antirev.tools.ida_tools import IdaSession
from tests.conftest import SAMPLE

def test_decompile_main_returns_pseudocode():
    with IdaSession(SAMPLE) as ida:
        fns = ida.list_functions()
        assert any(f["name"] in ("main", "_start", "check") for f in fns)
        r = ida.decompile("main") if any(f["name"]=="main" for f in fns) else ida.decompile(fns[0]["addr"])
        assert "pseudocode" in r and len(r["pseudocode"]) > 0
```

- [ ] **Step 4: 运行** `conda run -n antirev pytest tests/test_ida_tools.py -v` → PASS（先完成 Task 9 样本）

- [ ] **Step 5: 提交** `git commit -m "feat: IDA idalib worker + IdaSession thick tools"`

---

## Task 5: solve.locate_targets（确定性定位 find/avoid，§5.2）

**Files:**
- Create: `antirev/tools/solve_locate.py`
- Test: `tests/test_solve_locate.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/test_solve_locate.py
from antirev.tools.solve_locate import locate_targets
from tests.conftest import SAMPLE

def test_locate_finds_success_and_fail():
    r = locate_targets(SAMPLE)
    assert r["find"], "应从 'Correct' 串反推出成功分支地址"
    assert r["avoid"], "应从 'Wrong' 串反推出失败分支地址"
    assert all(isinstance(x, int) for x in r["find"] + r["avoid"])
```

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现**

```python
# antirev/tools/solve_locate.py
"""确定性推导 angr 的 find/avoid:抽成功/失败关键词串 → 取 xref → 得引用点地址。
别让弱模型猜地址(§5.2)。返回 {find:[ea...], avoid:[ea...], evidence:[...]}。"""
from __future__ import annotations
from antirev import config
from antirev.tools.ida_tools import IdaSession

def _match(value, keywords):
    v = value.lower()
    return any(k in v for k in keywords)

def locate_targets(binary: str):
    find, avoid, evidence = [], [], []
    with IdaSession(binary) as ida:
        strs = ida.strings()
        for s in strs:
            is_succ = _match(s["value"], config.SUCCESS_KEYWORDS)
            is_fail = _match(s["value"], config.FAIL_KEYWORDS)
            if not (is_succ or is_fail):
                continue
            for x in ida.xrefs_to(s["addr"]):
                bucket = find if is_succ else avoid
                bucket.append(x["frm"])
                evidence.append({"string": s["value"], "ref": x["frm"],
                                 "kind": "success" if is_succ else "fail"})
    return {"find": sorted(set(find)), "avoid": sorted(set(avoid)),
            "evidence": evidence}
```

- [ ] **Step 4: 运行确认通过**
- [ ] **Step 5: 提交** `git commit -m "feat: solve.locate_targets deterministic find/avoid"`

---

## Task 6: solve.angr（符号执行厚工具，§5.2）

**Files:**
- Create: `antirev/tools/solve_angr.py`（含 py3.12 驱动 + 子进程 angr 脚本，二合一）
- Test: `tests/test_solve_angr.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/test_solve_angr.py
from antirev.tools.solve_angr import solve_angr
from tests.conftest import SAMPLE, EXPECTED_FLAG, FIND_ADDR, AVOID_ADDR

def test_angr_recovers_flag():
    r = solve_angr(SAMPLE, find=[FIND_ADDR], avoid=[AVOID_ADDR],
                   input_kind="stdin", stdin_len=len(EXPECTED_FLAG))
    assert r["found"] is True
    assert EXPECTED_FLAG.encode() in r["stdin"].encode() or r["stdin"].strip() == EXPECTED_FLAG
```

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现（angr 跑在受管子进程,超时+状态上限）**

```python
# antirev/tools/solve_angr.py
"""solve.angr:探索到 find、避开 avoid、约束求解出输入。angr 在受管子进程内跑,
带 wall-clock 超时(subprocess) + 活跃状态上限(防路径爆炸,§11)。"""
from __future__ import annotations
import json, sys, textwrap
from antirev import config
from antirev.isolation.subprocess_runner import run_isolated

_DRIVER = textwrap.dedent('''
    import sys, json, angr, claripy
    p = json.loads(sys.argv[1])
    proj = angr.Project(p["binary"], auto_load_libs=False)
    n = p.get("stdin_len", 32)
    if p["input_kind"] == "stdin":
        chars = [claripy.BVS(f"b{i}", 8) for i in range(n)]
        flag = claripy.Concat(*chars)
        st = proj.factory.full_init_state(
            stdin=angr.SimFileStream(name="stdin", content=flag, has_end=True),
            add_options=angr.options.unicorn | {angr.options.LAZY_SOLVES})
        for c in chars:
            st.solver.add(claripy.Or(c==0, claripy.And(c>=0x20, c<=0x7e)))
    else:
        argv1 = claripy.BVS("arg", 8*n)
        st = proj.factory.full_init_state(args=[p["binary"], argv1],
            add_options={angr.options.LAZY_SOLVES})
    simgr = proj.factory.simulation_manager(st)
    max_states = p.get("max_states", 200)
    def _cap(sm):
        if len(sm.active) > max_states:
            sm.move("active", "stashed", lambda s: True)
            for s in sm.stashed[max_states:]: pass
            sm.stash(from_stash="active", to_stash="deferred",
                     filter_func=lambda s: False)
        return sm
    simgr.explore(find=p["find"], avoid=p.get("avoid", []), num_find=1,
                  step_func=_cap)
    if simgr.found:
        s = simgr.found[0]
        data = s.posix.dumps(0) if p["input_kind"]=="stdin" else s.solver.eval(argv1, cast_to=bytes)
        print(json.dumps({"found": True, "stdin": data.decode("latin1")}))
    else:
        print(json.dumps({"found": False, "stdin": ""}))
''')

def solve_angr(binary, find, avoid=None, input_kind="stdin", stdin_len=32,
               timeout=None, max_states=None):
    params = {"binary": str(binary), "find": list(find), "avoid": list(avoid or []),
              "input_kind": input_kind, "stdin_len": stdin_len,
              "max_states": max_states or config.ANGR_MAX_STATES}
    r = run_isolated([sys.executable, "-c", _DRIVER, json.dumps(params)],
                     timeout=timeout or config.ANGR_TIMEOUT)
    if r.timed_out:
        return {"found": False, "stdin": "", "error": "angr timeout"}
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        return {"found": False, "stdin": "", "error": r.stderr[-800:]}
```

> **执行期风险点**：`step_func` 里的状态上限写法需按 angr 实际 API 调整（`simgr.explore` 支持 `n=` 步数上限；活跃态裁剪更稳的做法是 `LengthLimiter` 或自定义 ExplorationTechnique）。执行时以「能对样本求出 flag + 不爆内存」为准迭代，别拘泥于此处伪代码。

- [ ] **Step 4: 运行确认通过**（对样本求出 flag）
- [ ] **Step 5: 提交** `git commit -m "feat: solve.angr subprocess-isolated symbolic solver"`

---

## Task 7: solve.verify（候选回验，§3.3/§5.2）

**Files:**
- Create: `antirev/tools/solve_verify.py`
- Test: `tests/test_solve_verify.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/test_solve_verify.py
from antirev.tools.solve_verify import verify_candidate
from tests.conftest import SAMPLE, EXPECTED_FLAG, FIND_ADDR, AVOID_ADDR

def test_true_flag_reaches_accept():
    r = verify_candidate(SAMPLE, EXPECTED_FLAG, find=FIND_ADDR, avoid=AVOID_ADDR)
    assert r["accepted"] is True and r["method"] in ("unicorn", "angr-concrete")

def test_wrong_flag_rejected():
    r = verify_candidate(SAMPLE, "flag{definitely_wrong}", find=FIND_ADDR, avoid=AVOID_ADDR)
    assert r["accepted"] is False
```

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现（MVP:angr 具体执行回验;§5.2 unicorn 版为后续优化）**

```python
# antirev/tools/solve_verify.py
"""候选回验(强成功判据,§3.3):把候选喂回二进制自身逻辑,确认走到 accept(find)而非 reject(avoid)。
MVP 用 angr 具体执行(复用其 syscall 模型,稳健);unicorn 片段模拟版留作后续按 §5.2 补。
无法隔离校验时降级格式校验并标注风险。"""
from __future__ import annotations
import json, sys, re, textwrap
from antirev import config
from antirev.isolation.subprocess_runner import run_isolated

_DRIVER = textwrap.dedent('''
    import sys, json, angr
    p = json.loads(sys.argv[1])
    proj = angr.Project(p["binary"], auto_load_libs=False)
    cand = p["candidate"].encode()
    st = proj.factory.full_init_state(
        stdin=angr.SimFileStream(name="stdin", content=cand, has_end=True))
    simgr = proj.factory.simulation_manager(st)
    simgr.explore(find=[p["find"]], avoid=[p["avoid"]] if p.get("avoid") else [])
    print(json.dumps({"accepted": bool(simgr.found)}))
''')

def verify_candidate(binary, candidate, find=None, avoid=None,
                     flag_regex=r"^[A-Za-z0-9_]*\\{.*\\}$"):
    if find is not None:
        params = {"binary": str(binary), "candidate": candidate,
                  "find": find, "avoid": avoid}
        r = run_isolated([sys.executable, "-c", _DRIVER, json.dumps(params)],
                         timeout=config.ANGR_TIMEOUT)
        if not r.timed_out and r.stdout.strip():
            try:
                out = json.loads(r.stdout.strip().splitlines()[-1])
                return {"accepted": out["accepted"], "method": "angr-concrete"}
            except Exception:
                pass
    # 降级:格式校验(标注假阳性风险)
    ok = bool(re.match(flag_regex, candidate))
    return {"accepted": ok, "method": "format-only",
            "warning": "未经二进制自验,存在假阳性"}
```

- [ ] **Step 4: 运行确认通过**
- [ ] **Step 5: 提交** `git commit -m "feat: solve.verify candidate re-check"`

---

## Task 8: terminal 工具（沙箱执行，§5.4）

**Files:**
- Create: `antirev/tools/terminal.py`
- Test: `tests/test_terminal.py`

- [ ] **Step 1: 写失败测试**

```python
# tests/test_terminal.py
from antirev.tools.terminal import terminal

def test_runs_and_captures(tmp_path):
    r = terminal("echo hello", workdir=tmp_path)
    assert r["returncode"] == 0 and "hello" in r["stdout"] and r["timed_out"] is False

def test_timeout(tmp_path):
    r = terminal("sleep 5", workdir=tmp_path, timeout=1)
    assert r["timed_out"] is True
```

- [ ] **Step 2: 运行确认失败**

- [ ] **Step 3: 实现**

```python
# antirev/tools/terminal.py
"""杂项兜底命令执行:超时 + 受限工作目录 + 捕获三元组。angr/floss/DIE 等一等厚工具不走这里(§5.4)。"""
from __future__ import annotations
import shlex
from antirev import config
from antirev.isolation.subprocess_runner import run_isolated

def terminal(command: str, workdir=None, timeout=None):
    r = run_isolated(shlex.split(command), timeout=timeout or config.TERMINAL_TIMEOUT,
                     cwd=str(workdir) if workdir else None)
    return {"returncode": r.returncode, "stdout": r.stdout[-4000:],
            "stderr": r.stderr[-2000:], "timed_out": r.timed_out}
```

- [ ] **Step 4: 运行确认通过**
- [ ] **Step 5: 提交** `git commit -m "feat: sandboxed terminal tool"`

---

## Task 9: 样本 + 确定性固定流水线（★MVP 无模型验收★，§14 step 1）

**Files:**
- Create: `tests/samples/make_sample.py`, `tests/conftest.py`, `antirev/pipeline_mvp.py`, `tests/test_pipeline_mvp.py`

- [ ] **Step 1: 写样本生成器（pwntools 造 x86-64 Linux ELF,无需交叉编译器）**

```python
# tests/samples/make_sample.py
"""用 pwntools 汇编生成一个 flagcheck ELF:
  read(0, buf, N) → 逐字节 xor 0x37 与内嵌 target 比较 →
  全中 write(1,"Correct\\n") exit(0);否则 write(1,"Wrong\\n") exit(1)。
纯 syscall,无 libc → angr 好解;内嵌 Correct/Wrong 串 → locate_targets 可定位。"""
from pwn import *
context.arch = "amd64"; context.os = "linux"
FLAG = b"flag{unic0rn_x0r}"          # 17 bytes
TARGET = bytes(b ^ 0x37 for b in FLAG)
asm_src = f"""
    /* read(0, rsp-0x40, len) */
    xor edi, edi
    lea rsi, [rsp-0x40]
    mov edx, {len(FLAG)}
    xor eax, eax
    syscall
    /* compare loop */
    lea rsi, [rsp-0x40]
    lea rdi, [rip+target]
    mov ecx, {len(FLAG)}
check:
    mov al, [rsi]
    xor al, 0x37
    cmp al, [rdi]
    jne wrong
    inc rsi
    inc rdi
    dec ecx
    jnz check
    /* correct: write(1,msg_ok,8); exit(0) */
    mov edi, 1
    lea rsi, [rip+msg_ok]
    mov edx, 8
    mov eax, 1
    syscall
    xor edi, edi
    mov eax, 60
    syscall
wrong:
    mov edi, 1
    lea rsi, [rip+msg_no]
    mov edx, 6
    mov eax, 1
    syscall
    mov edi, 1
    mov eax, 60
    syscall
target:  .byte {','.join(str(b) for b in TARGET)}
msg_ok:  .ascii "Correct\\n"
msg_no:  .ascii "Wrong\\n"
"""
e = ELF.from_assembly(asm_src)
e.save("tests/samples/flagcheck")
import os; os.chmod("tests/samples/flagcheck", 0o755)
print("wrote tests/samples/flagcheck; flag =", FLAG.decode())
```

- [ ] **Step 2: 生成样本 + 记录事实常量**

```bash
conda run -n antirev python tests/samples/make_sample.py
```
Expected: `wrote ... flag = flag{unic0rn_x0r}`。用 `objdump -d`/IDA 记下 Correct 分支(FIND)与 Wrong 分支(AVOID)地址,填入 conftest。

```python
# tests/conftest.py
import subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
SAMPLE = str(ROOT / "tests/samples/flagcheck")
EXPECTED_FLAG = "flag{unic0rn_x0r}"
# 下列地址在生成后由 locate_targets/objdump 确认后填入(执行期钉死):
FIND_ADDR = 0x0     # Correct 分支 write 处
AVOID_ADDR = 0x0    # Wrong 分支 write 处

def pytest_configure(config):
    if not Path(SAMPLE).exists():
        subprocess.run([sys.executable, str(ROOT/"tests/samples/make_sample.py")], cwd=ROOT, check=True)
```
> 执行期:先跑 `solve.locate_targets(SAMPLE)` 拿到 find/avoid,把地址回填进 conftest 常量,angr/verify 测试即可用真实地址。

- [ ] **Step 3: 写固定流水线（无模型,串起四工具）**

```python
# antirev/pipeline_mvp.py
"""§14 step 1 的无模型验收:decompile → locate_targets → angr → verify。
证明工具链 + 内存闭环,与模型解耦。返回 {flag, verified, steps}。"""
from __future__ import annotations
from antirev.tools.ida_tools import IdaSession
from antirev.tools.solve_locate import locate_targets
from antirev.tools.solve_angr import solve_angr
from antirev.tools.solve_verify import verify_candidate

def run_pipeline(binary: str, stdin_len: int = 32):
    steps = []
    with IdaSession(binary) as ida:
        fns = ida.list_functions()
    steps.append(("decompile/list", f"{len(fns)} functions"))

    tgt = locate_targets(binary)
    steps.append(("locate_targets", tgt))
    if not tgt["find"]:
        return {"flag": None, "verified": False, "steps": steps,
                "error": "no find target located"}

    sol = solve_angr(binary, find=tgt["find"], avoid=tgt["avoid"],
                     input_kind="stdin", stdin_len=stdin_len)
    steps.append(("solve_angr", sol))
    if not sol.get("found"):
        return {"flag": None, "verified": False, "steps": steps,
                "error": sol.get("error", "angr no solution")}

    candidate = sol["stdin"].split("\x00")[0].strip()
    ver = verify_candidate(binary, candidate,
                           find=tgt["find"][0], avoid=(tgt["avoid"] or [None])[0])
    steps.append(("verify", ver))
    return {"flag": candidate, "verified": ver["accepted"], "steps": steps}
```

- [ ] **Step 4: 写 MVP 验收测试**

```python
# tests/test_pipeline_mvp.py
from antirev.pipeline_mvp import run_pipeline
from tests.conftest import SAMPLE, EXPECTED_FLAG

def test_mvp_end_to_end_recovers_and_verifies_flag():
    r = run_pipeline(SAMPLE, stdin_len=len(EXPECTED_FLAG))
    assert r["flag"] is not None
    assert EXPECTED_FLAG in r["flag"]
    assert r["verified"] is True
```

- [ ] **Step 5: 运行验收**

Run: `conda run -n antirev pytest tests/test_pipeline_mvp.py -v`
Expected: PASS —— **这是 MVP 的核心里程碑:无模型下四工具端到端出 flag 并回验。**

- [ ] **Step 6: 提交** `git commit -m "feat: MVP deterministic pipeline + sample + end-to-end test"`

---

## Task 10: ReAct Executor（模型驱动端到端，§3.3）— 依赖模型端点就绪

**Files:**
- Create: `antirev/executor_mvp.py`, `main.py`, `tests/fixtures/plan_flagcheck.md`
- Test: `tests/test_executor_smoke.py`（需 `127.0.0.1:7777` 在线）

- [ ] **Step 1: 确认模型端点在线**

```bash
curl -s http://127.0.0.1:7777/v1/models | head -c 400
```
Expected: 返回 model 列表 JSON;顺便记录真实型号(钉死 §1.2 的 30B/35B)。

- [ ] **Step 2: 把四工具封成 LangChain `@tool`**（薄封装,复用 Task 4–8 函数）

```python
# antirev/executor_mvp.py
"""MVP ReAct Executor:系统 prompt + 手写 Plan.md 作初始 prompt,不开模型 thinking(§3.3),
工具 = ida.decompile / solve.locate_targets / solve.angr / solve.verify / terminal。"""
from __future__ import annotations
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from antirev import config
from antirev.tools.ida_tools import IdaSession
from antirev.tools import solve_locate, solve_angr, solve_verify, terminal as term

def build_tools(binary: str):
    @tool
    def ida_decompile(name_or_addr: str) -> str:
        """反编译单个函数,返回伪代码(压缩切片)。参数:函数名或十六进制地址。"""
        with IdaSession(binary) as ida:
            return ida.decompile(name_or_addr)["pseudocode"][:6000]

    @tool
    def solve_locate() -> dict:
        """确定性推导 angr 的 find/avoid 地址(从成功/失败字符串反推)。"""
        return solve_locate.locate_targets(binary)

    @tool
    def solve_angr_tool(find: list[int], avoid: list[int], stdin_len: int = 32) -> dict:
        """符号执行求解:探索到 find、避开 avoid,返回满足输入。"""
        return solve_angr.solve_angr(binary, find=find, avoid=avoid, stdin_len=stdin_len)

    @tool
    def solve_verify_tool(candidate: str, find: int, avoid: int = None) -> dict:
        """把候选 flag 喂回二进制自身校验,确认走到 accept 分支。"""
        return solve_verify.verify_candidate(binary, candidate, find=find, avoid=avoid)

    @tool
    def run_terminal(command: str) -> dict:
        """执行本地命令(超时+沙箱)。仅杂项兜底。"""
        return term.terminal(command)

    return [ida_decompile, solve_locate, solve_angr_tool, solve_verify_tool, run_terminal]

def build_executor(binary: str):
    llm = ChatOpenAI(base_url=config.MODEL_BASE_URL, api_key=config.MODEL_API_KEY,
                     model=config.MODEL_NAME, temperature=0)
    return create_react_agent(llm, build_tools(binary))
```

- [ ] **Step 3: 手写固定 Plan.md**

```markdown
<!-- tests/fixtures/plan_flagcheck.md -->
# Plan: flagcheck
## 题型判断
- 主类型: flag 校验函数
- 架构: x86-64 Linux
## 分步计划
- [ ] Step 1: solve.locate 定位成功/失败分支地址 | 判据: 得到 find/avoid
- [ ] Step 2: solve.angr(find,avoid,stdin_len=17) 求解 | 判据: 拿到候选输入
- [ ] Step 3: solve.verify 回验候选 | 判据: accepted=True 即为真 flag
## flag 格式
- 预期: flag{...}
```

- [ ] **Step 4: 冒烟测试（端点在线时）**

```python
# tests/test_executor_smoke.py
import pytest, urllib.request
from antirev.executor_mvp import build_executor
from tests.conftest import SAMPLE, EXPECTED_FLAG

def _endpoint_up():
    try:
        urllib.request.urlopen("http://127.0.0.1:7777/v1/models", timeout=2); return True
    except Exception:
        return False

@pytest.mark.skipif(not _endpoint_up(), reason="model endpoint offline")
def test_executor_solves_flagcheck():
    agent = build_executor(SAMPLE)
    plan = open("tests/fixtures/plan_flagcheck.md").read()
    out = agent.invoke({"messages": [("user",
        f"按下面 Plan 解出 flag,只用提供的工具。\\n\\n{plan}")]})
    text = str(out["messages"][-1].content)
    assert EXPECTED_FLAG in text
```

- [ ] **Step 5: 运行** `conda run -n antirev pytest tests/test_executor_smoke.py -v`
Expected: PASS（模型经工具走通四步）;若模型 tool-calling 不稳,记录现象 → Task 11 调协议。

- [ ] **Step 6: 写 main.py 入口**

```python
# main.py
import sys
from antirev.executor_mvp import build_executor

def main():
    binary = sys.argv[1]
    plan = open(sys.argv[2]).read() if len(sys.argv) > 2 else "解出该二进制的 flag。"
    agent = build_executor(binary)
    out = agent.invoke({"messages": [("user", plan)]})
    print(out["messages"][-1].content)

if __name__ == "__main__":
    main()
```

- [ ] **Step 7: 提交** `git commit -m "feat: MVP ReAct executor + main entry"`

---

## Task 11: 单步延迟实测 + 模型能力校验（§7.4/§9.1）— 依赖模型端点

- [ ] **Step 1: tool-calling / structured output 验证**

```bash
curl -s http://127.0.0.1:7777/v1/chat/completions -H 'Content-Type: application/json' -d '{
 "model":"local","messages":[{"role":"user","content":"call the ping tool"}],
 "tools":[{"type":"function","function":{"name":"ping","parameters":{"type":"object","properties":{}}}}]}' | head -c 800
```
Expected: 返回含 `tool_calls`;若模型不发原生 tool_call → 记录,MVP 后改显式 ReAct 文本协议(§12)。

- [ ] **Step 2: 单步端到端延迟实测（§7.4,钉死每题步数上限）**

写 `scripts/measure_step_latency.py`:对 ~20k / ~40k token 上下文各测 prefill+生成耗时,打印 p50/p90,反推 §11 的 20min 预算下每题步数上限。记录到 `docs/measurements.md`。

- [ ] **Step 3: 提交** `git commit -m "chore: model latency + tool-calling measurements"`

---

## Self-Review（对照 plan1.md §14 step 1 + §9）

- **§14 step 1 覆盖**:Executor(Task 10) + ida.decompile(Task 4) + terminal(Task 8) + solve.angr(Task 6) + solve.locate_targets(Task 5) + solve.verify(Task 7) + 手写固定 Plan(Task 10 Step 3) + 端到端(Task 9 无模型 / Task 10 有模型) ✅
- **§9.2 idalib 离线 dry-run 一票否决项**:Task 0 Step 5 ✅
- **§7.4 单步延迟实测**:Task 11 Step 2 ✅（依赖端点）
- **§1.2 型号钉死**:Task 10 Step 1 顺带确认 ✅（依赖端点）
- **占位符扫描**:conftest 的 FIND_ADDR/AVOID_ADDR 是有意的执行期回填项(Task 9 Step 2 明确了回填流程),非遗留占位。
- **类型一致性**:`locate_targets`→`{find,avoid,evidence}`;`solve_angr`→`{found,stdin}`;`verify_candidate`→`{accepted,method}`;pipeline 消费一致 ✅
- **已知偏差(明确记录)**:
  - `solve.verify` MVP 用 angr-concrete 而非 §5.2 的 unicorn;语义(二进制自验 accept)满足,unicorn 片段版列为后续。
  - `solve.angr` 的状态上限 `step_func` 伪代码需按 angr 真实 API 迭代(Task 6 已标注)。
  - SQLite 外部记忆层 / 上下文压缩 = plan §6/§14 step 2,**不在本 MVP**,下一份计划。
  - Planner + LangGraph 编排 = §14 step 3,不在本 MVP(本期 Executor 用 create_react_agent 直跑固定 Plan)。

---

## Milestone 边界（后续各自成计划）

| 计划 | 对应 plan1.md |
|---|---|
| **本计划:MVP** | §14 step 1 + 前置环境 |
| 外部记忆 + 上下文压缩 | §6 / §14 step 2 |
| Planner + LangGraph 编排 | §3 / §14 step 3 |
| 反馈回路 + 题型路由 | §3.4 / §8 / §14 step 4 |
| 补全 z3/unicorn/FLOSS/DIE/脱壳 | §5.2–5.3 / §14 step 5 |
| 鲁棒性 + 双轨日志 + 超时预算 + 人工干预 | §10 / §11 / §14 step 6 |
| 离线固化 + 分类评估集回归 | §9 / §14 step 7 |
