"""FastAPI 路由 + SSE 编排 + 静态文件。

Web 与 agent 之间只有两条通道:读 logs/<run_id>.jsonl(事件流)、写 .ctl/.hint(控制)。
不 import 任何解题逻辑 —— agent 崩了 Web 照活,Web 崩了 agent 照跑。
"""
from __future__ import annotations
import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from antirev import config, ctl
from antirev.web import control, runner
from antirev.web.tailer import JsonlTailer, read_event

STATIC = Path(__file__).parent / "static"
SSE_INTERVAL = 0.5        # SSE 轮询间隔(秒)


@asynccontextmanager
async def lifespan(app):
    runner.adopt_orphans()   # Web 重启后接管仍在跑的 run(子进程是 start_new_session,不随 Web 死)
    yield


app = FastAPI(title="antiReverse Web 作战台", lifespan=lifespan)


class StartReq(BaseModel):
    binary: str
    max_replan: int = 9999
    max_steps: int = 15
    budget: int = 3600
    stuck_seconds: int = 600
    hint: str | None = None
    run_id: str | None = None
    force: bool = False       # 已有活跃 run 时强制再起一个


class ControlReq(BaseModel):
    action: str


class HintReq(BaseModel):
    text: str


def _safe_path(raw: str) -> Path:
    """路径必须在 PROJECT_ROOT 之内,挡目录穿越。"""
    p = Path(raw).expanduser().resolve()
    root = Path(config.PROJECT_ROOT).resolve()
    if root not in p.parents and p != root:
        raise HTTPException(400, f"路径必须在 PROJECT_ROOT({root})之内")
    return p


@app.middleware("http")
async def _no_store_static(request: Request, call_next):
    """静态资源禁缓存。

    本机单人工具,没有带宽顾虑;而 index.html / app.js 走浏览器缓存的话,改完前端要教人
    按硬刷新才看得到(实测改了文案后页面仍显示旧版,误判成代码没生效)。
    """
    resp = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/fs/browse")
def browse(path: str = ""):
    """服务端目录浏览。默认根 data/(题库) —— 因为题面 description.md 要在二进制同级目录找。"""
    base = _safe_path(path) if path else Path(config.PROJECT_ROOT) / "data"
    if not base.exists():
        base = Path(config.PROJECT_ROOT)
    if base.is_file():
        base = base.parent
    entries = []
    for e in sorted(base.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
        if e.name.startswith("."):
            continue
        try:
            size = e.stat().st_size if e.is_file() else 0
        except OSError:
            continue
        entries.append({"name": e.name, "path": str(e), "is_dir": e.is_dir(), "size": size})
    parent = str(base.parent) if base != Path(config.PROJECT_ROOT).resolve() else None
    return {"path": str(base), "parent": parent, "entries": entries}


@app.get("/api/runs")
def list_runs():
    return {"runs": runner.list_runs(), "active": runner.active_run_ids()}


@app.post("/api/runs")
def start_run(req: StartReq):
    binary = Path(req.binary).expanduser()
    # 必须 is_file 而不是 exists:空字符串的 Path 是 ".",而目录是"存在"的 —— 用 exists 会让
    # 空 binary 一路放行到 solve_one,起一个注定失败的子进程(实测踩过)。
    if not binary.is_file():
        raise HTTPException(400, f"二进制不存在或不是文件: {req.binary}")
    _safe_path(str(binary))
    active = runner.active_run_ids()
    if active and not req.force:
        raise HTTPException(409, f"已有活跃 run {active};并行会抢 mlx 缓存与内存。"
                                 f"确认要并行请带 force=true")
    rid = runner.start(binary=str(binary), max_replan=req.max_replan, max_steps=req.max_steps,
                       budget=req.budget, stuck_seconds=req.stuck_seconds, run_id=req.run_id)
    if req.hint:
        control.append_hint(rid, req.hint)
    return {"run_id": rid, "status": runner.status(rid)}


@app.get("/api/runs/{run_id}/status")
def run_status(run_id: str):
    return runner.status(run_id)


@app.get("/api/runs/{run_id}/result")
def run_result(run_id: str):
    return runner.result_of(run_id) or {"status": "pending"}


@app.post("/api/runs/{run_id}/control")
def run_control(run_id: str, req: ControlReq):
    if req.action == "stop":
        res = runner.stop(run_id)
        return {"state": "stopping", **res}
    try:
        return {"state": control.apply_action(run_id, req.action)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/runs/{run_id}/hint")
def run_hint(run_id: str, req: HintReq):
    try:
        return {"line": control.append_hint(run_id, req.text)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/runs/{run_id}/hints")
def run_hints(run_id: str):
    return {"hints": control.read_hints(run_id)}


@app.get("/api/runs/{run_id}/events/{seq}")
def run_event(run_id: str, seq: int, offset: int = 0, limit: int = 262144):
    rec = read_event(runner.jsonl_path(run_id), seq, offset, min(limit, 262144))
    if rec is None:
        raise HTTPException(404, f"事件 {seq} 不存在")
    return rec


def _sse(event: str, data: dict, seq=None) -> str:
    head = f"id: {seq}\n" if seq is not None else ""
    return f"{head}event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@app.get("/api/runs/{run_id}/stream")
async def stream(run_id: str, request: Request,
                 from_seq: int = 0,
                 last_event_id: str | None = Header(None, alias="Last-Event-ID")):
    """SSE 事件流。断线重连时浏览器自动带 Last-Event-ID,据此续传不重放。"""
    start_seq = int(last_event_id) if (last_event_id or "").isdigit() else from_seq

    async def gen():
        ev_tail = JsonlTailer(runner.jsonl_path(run_id))
        tps_tail = JsonlTailer(runner.tps_path(run_id))
        last_status = None
        while True:
            if await request.is_disconnected():
                break
            # tailer.poll 是同步阻塞 IO(可能读 1MB 的行),丢到线程里免得卡住事件循环
            for ev in await asyncio.to_thread(ev_tail.poll):
                if ev["seq"] > start_seq:
                    yield _sse("agent", ev, seq=ev["seq"])
            for m in await asyncio.to_thread(tps_tail.poll):
                yield _sse("metric", m)
            st = await asyncio.to_thread(runner.status, run_id)
            if st != last_status:
                last_status = st
                yield _sse("status", st)
            if not st["alive"] and ev_tail.at_eof():
                yield _sse("end", {"run_id": run_id,
                                   "result": runner.result_of(run_id) or {}})
                break
            await asyncio.sleep(SSE_INTERVAL)

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"})


app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


def main():
    import uvicorn
    STATIC.mkdir(parents=True, exist_ok=True)
    uvicorn.run(app, host="127.0.0.1", port=8765, log_level="info")


if __name__ == "__main__":
    main()
