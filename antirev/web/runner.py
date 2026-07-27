"""run 生命周期:起子进程、探测猝死、停止(信号优先 killpg 兜底)、重启接管孤儿。

进程模型沿用 scripts/eval.py 已验证的那一套 —— 按题一个子进程 + 可硬杀。这不是洁癖:
angr/IDA 会段错误,agent 必须活在独立进程里,否则会把 Web 一起拖走。
"""
from __future__ import annotations
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from antirev import config, ctl

STOP_GRACE_S = 15        # 发信号后等优雅退出的秒数,超时才 killpg
REGISTRY: dict = {}      # run_id -> Run(仅本进程起的/已接管的)


class Run:
    def __init__(self, run_id, binary, proc=None, pid=None, tps_path=None):
        self.run_id = run_id
        self.binary = binary
        self.proc = proc                       # 本进程起的才有 Popen;接管的孤儿为 None
        self.pid = pid if pid is not None else (proc.pid if proc else None)
        self.tps_path = tps_path
        self.started = time.time()

    def alive(self) -> bool:
        if self.proc is not None:
            return self.proc.poll() is None
        return _pid_alive(self.pid)

    def exit_code(self):
        return self.proc.poll() if self.proc is not None else None


def _pid_alive(pid) -> bool:
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except (ProcessLookupError, ValueError):
        return False
    except PermissionError:
        return True                            # 存在但不属于我们


def _log_dir() -> Path:
    d = Path(config.LOG_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def jsonl_path(run_id) -> Path:
    return _log_dir() / f"{run_id}.jsonl"


def tps_path(run_id) -> Path:
    return _log_dir() / f"{run_id}.tps.jsonl"


def stdout_path(run_id) -> Path:
    return _log_dir() / f"{run_id}.stdout.log"


def new_run_id() -> str:
    """web_<日期时间>,已存在则加序号(同秒两次启动也不撞)。"""
    base = "web_" + time.strftime("%Y%m%d_%H%M%S")
    rid, n = base, 2
    while jsonl_path(rid).exists() or ctl.ctl_path(rid).exists():
        rid, n = f"{base}_{n}", n + 1
    return rid


def start_script(argv: list, run_id: str, binary: str) -> str:
    """起一个 python 子进程(argv 接在 sys.executable 之后)。返回 run_id。

    stdout/stderr **必须重定向到文件**:solve_one 的 stdout 有海量 IDA/angr 噪声,
    用 PIPE 且不读会撑满 64KB 管道缓冲把子进程永久卡死。
    """
    tps = str(tps_path(run_id))
    # ANTIREV_LOG_DIR 必须显式传:子进程会重新 import config,只认环境变量(config.py:29)。
    # 不传的话,父进程运行时改过的 LOG_DIR(测试 monkeypatch、或将来多目录部署)对子进程无效,
    # 子进程会把 jsonl/.ctl 写到默认 logs/ 去,Web 就 tail 了个空文件。
    env = {**os.environ, "TPS_METRICS_PATH": tps, "ANTIREV_LOG_DIR": str(_log_dir())}
    log = open(stdout_path(run_id), "ab")
    try:
        proc = subprocess.Popen(
            [sys.executable, *argv],
            cwd=str(config.PROJECT_ROOT), stdout=log, stderr=log,
            start_new_session=True, env=env,   # 独立进程组:Web 死了它照跑,也便于整组回收
        )
    finally:
        log.close()                            # 子进程已继承 fd,父进程不必留着
    ctl.write_state(run_id, "running", pid=proc.pid)
    REGISTRY[run_id] = Run(run_id, binary, proc=proc, tps_path=tps)
    return run_id


def start(binary: str, max_replan: int = 9999, max_steps: int = 15,
          budget: int = 3600, stuck_seconds: int = 600, run_id: str | None = None) -> str:
    """起一道真题。budget 等参数必须是整数 —— solve_one.py 会 int() 这些 argv。"""
    rid = run_id or new_run_id()
    argv = ["-m", "antirev.solve_one", str(binary), rid,
            str(int(max_replan)), str(int(max_steps)), str(int(budget)), str(int(stuck_seconds))]
    return start_script(argv, run_id=rid, binary=str(binary))


def active_run_ids() -> list:
    return [rid for rid, r in REGISTRY.items() if r.alive()]


def status(run_id: str) -> dict:
    """当前状态。state 取值:running/paused/stopping/done/crashed/unknown。"""
    run = REGISTRY.get(run_id)
    alive = run.alive() if run else _pid_alive(ctl.read_pid(run_id))
    code = run.exit_code() if run else None
    if alive:
        state = ctl.read_state(run_id)
    elif code not in (None, 0):
        state = "crashed"
    elif run is not None or ctl.ctl_path(run_id).exists() or jsonl_path(run_id).exists():
        # 有 jsonl 就说明这个 run 真跑过 —— 回放历史 run 时要显示"已结束",不能是"未知"。
        # 只有既无日志也无 .ctl 的 run_id 才是真的不存在。
        state = "done"
    else:
        state = "unknown"
    out = {"run_id": run_id, "alive": alive, "state": state, "exit_code": code,
           "binary": run.binary if run else None,
           "started": run.started if run else None}
    if state == "crashed":
        out["stderr_tail"] = _stdout_tail(run_id)
    return out


def _stdout_tail(run_id: str, n: int = 2000) -> str:
    p = stdout_path(run_id)
    if not p.exists():
        return ""
    return p.read_bytes()[-n:].decode("utf-8", errors="replace")


def result_of(run_id: str):
    """从 stdout 里捞 solve_one 的 __RESULT__ 行(最后一条)。"""
    for ln in reversed(_stdout_tail(run_id, 65536).splitlines()):
        if ln.startswith("__RESULT__"):
            try:
                return json.loads(ln[len("__RESULT__"):])
            except Exception:
                return None
    return None


def stop(run_id: str, grace: float = STOP_GRACE_S) -> dict:
    """停止:SIGTERM 主路径(即时打断阻塞调用),.ctl=stopping 兜底,killpg 最后手段。"""
    run = REGISTRY.get(run_id)
    pid = run.pid if run else ctl.read_pid(run_id)
    try:
        ctl.write_state(run_id, "stopping")    # 兜底:信号丢了,下一个检查点也会停
    except Exception:
        pass
    if pid:
        try:
            os.kill(int(pid), signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass
    t0 = time.time()
    while time.time() - t0 < grace:
        if not (run.alive() if run else _pid_alive(pid)):
            return {"stopped": "graceful"}
        time.sleep(0.3)
    hard = _hard_kill(pid)
    return {"stopped": "killed", "killpg": hard, "orphans": reap_orphan_ida()}


def _hard_kill(pid) -> bool:
    if not pid:
        return False
    try:
        os.killpg(os.getpgid(int(pid)), signal.SIGKILL)
        return True
    except Exception:
        try:
            os.kill(int(pid), signal.SIGKILL)
            return True
        except Exception:
            return False


def reap_orphan_ida() -> list:
    """清掉父进程已消失的 IDA worker。

    只在 killpg 兜底路径需要:IdaSession 用 start_new_session 起 worker
    (tools/ida_tools.py:46),它自成进程组,killpg 掉 solve_one 杀不到它。正常停止走
    run() 的 finally → _close_ida()(ida_tools.py:69)才是真正杀它的地方。
    """
    killed = []
    try:
        import psutil
    except ImportError:
        return killed
    for p in psutil.process_iter(["pid", "ppid", "cmdline"]):
        try:
            cmd = " ".join(p.info.get("cmdline") or [])
            if "ida_worker.py" not in cmd or p.info.get("ppid") != 1:
                continue
            p.kill()
            killed.append(p.info["pid"])
        except Exception:
            continue
    return killed


def adopt_orphans() -> list:
    """Web 重启后扫 logs/*.ctl,把 pid 仍活着的 run 重新纳入注册表。

    子进程是 start_new_session 起的,Web 死了它照跑 —— 不接管的话界面上会看不到
    正在解题的 run。
    """
    adopted = []
    for p in sorted(_log_dir().glob("*.ctl")):
        rid = p.stem
        if rid in REGISTRY:
            continue
        pid = ctl.read_pid(rid)
        if not _pid_alive(pid):
            continue
        REGISTRY[rid] = Run(rid, binary=None, pid=pid, tps_path=str(tps_path(rid)))
        adopted.append(rid)
    return adopted


def list_runs() -> list:
    """所有 run(活跃 + 历史)。历史靠扫 logs/*.jsonl 发现,可直接回放。"""
    out, seen = [], set()
    for rid in active_run_ids():
        out.append(status(rid))
        seen.add(rid)
    for p in sorted(_log_dir().glob("*.jsonl"), key=lambda x: -x.stat().st_mtime):
        rid = p.stem
        if rid in seen or rid.endswith(".tps"):
            continue
        seen.add(rid)
        out.append({"run_id": rid, "alive": False, "state": "history",
                    "mtime": round(p.stat().st_mtime, 1), "size": p.stat().st_size})
    return out
