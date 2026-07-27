# antirev.web — Web 作战台

单题作战台：输入参数 → 开跑 → 实时看每一步在干什么 → 暂停 → 丢提示 → 继续 → 停止。

## 启动

```bash
# 1. mlx 端点要先在 7777 上(Web 不管 mlx 生命周期,由你自己起)
# 2. 起 Web
conda run -n antirev python -m antirev.web.server
# 3. 浏览器打开
open http://127.0.0.1:8765
```

深链 `http://127.0.0.1:8765/#<run_id>` 直接进入某个 run——刷新页面不丢现场，也可用于回放历史 run。

## 核心设计

Web **只当日志消费者 + 控制文件写入者**，不参与解题、不 import 任何解题逻辑：

| 通道 | 方向 | 载体 |
|---|---|---|
| 事件流 | agent → Web | tail `logs/<run_id>.jsonl`（`RunLogger` 已有的完整事件流，**无新埋点**） |
| 性能指标 | agent → Web | tail `logs/<run_id>.tps.jsonl`（起进程时设 `TPS_METRICS_PATH`，零内核改动白拿 prefill/tps/内存曲线） |
| 暂停/恢复 | Web → agent | 写 `logs/<run_id>.ctl`，agent 在检查点轮询 |
| 人工提示 | Web → agent | **append** `logs/<run_id>.hint`（必须追加，见下） |
| 停止 | Web → agent | `SIGTERM` → `StopRequested` → agent 的 `finally` 优雅清理；15s 不退再 `killpg` |

因此：**Web 崩了 agent 照跑，agent 崩了 Web 照活**，历史 run 用同一套渲染直接回放。

## 三个反直觉的实现约束

1. **`StopRequested` 必须继承 `BaseException`。** `react_executor.py` 里有一句 `except Exception: continue`——普通异常会被它吞掉，停止请求退化成"跳过一步继续跑"。

2. **暂停时长必须从三个时间闸里扣掉**（`start` / `progress["last"]` / `progress["deadline"]`）。否则暂停 10 分钟直接被 `stuck_no_progress`（默认 600s）判死。`deadline` 为此从闭包参数搬进了共享的 `progress` dict。

3. **`.hint` 必须追加写且每行带唯一前缀。** agent 的去重判据是 `_h not in ctx.user_hints`（子串判断，读文件全量内容）。覆盖写时，第二条提示只要是第一条的子串就会被**静默丢弃**——界面显示"已发送"其实没生效。`[#N 时间]` 前缀杜绝这种情况。

## 暂停的三个检查点

| 位置 | 语义 |
|---|---|
| executor 步开头 | 稳态暂停：上一步已完、下一步未想 |
| **executor 决策后 / 工具执行前** | **HITL 最有价值的位置**——前端此刻已收到 `thought`+`tool`+`args`，你能在它白花 180s 做无用 IDA 分析**之前**拦住 |
| planner 入口 | 轮次边界暂停 |

## 模块

| 文件 | 职责 | 测试 |
|---|---|---|
| `server.py` | FastAPI 路由 + SSE 编排 + 静态文件 | 21 |
| `runner.py` | 起停子进程、猝死探测、孤儿接管、IDA 孤儿回收 | 11 |
| `tailer.py` | jsonl 增量读取（按字节缓冲不完整行） | 14 |
| `control.py` | `.hint` / `.ctl` 写入 | 8 |
| `static/` | 零构建前端（原生 ES module，无框架无打包无 CDN） | 视觉验收 |

agent 侧的检查点在 `antirev/ctl.py`（15 个测试）——刻意放在本包**外面**，因为 agent 不该 import 任何 web 代码，两者之间只有 `.ctl` 文件这一个契约。

## API

| 方法 | 路径 | 作用 |
|---|---|---|
| `GET` | `/api/fs/browse?path=` | 服务端目录浏览（默认根 `data/`，限制在 `PROJECT_ROOT` 内） |
| `GET`/`POST` | `/api/runs` | run 列表 / 启动新 run |
| `GET` | `/api/runs/{id}/status`、`/result`、`/hints` | 状态 / `__RESULT__` / 已发提示 |
| `POST` | `/api/runs/{id}/control` | `{action: pause\|resume\|stop}` |
| `POST` | `/api/runs/{id}/hint` | 追加提示 |
| `GET` | `/api/runs/{id}/events/{seq}` | 某条事件全文（长字段可分页，单次上限 256KB） |
| `GET` | `/api/runs/{id}/stream` | **SSE**：`agent` / `metric` / `status` / `end` 四类事件 |

SSE 用事件的 `seq`（= jsonl 行号）作 `id:`，浏览器重连自动带 `Last-Event-ID`，据此续传不重放。

## 界面读法

侧栏「上下文」水位条有两道线，对应 agent 的分层压缩阈值：超 **32k**（`L1_TOKEN_THRESHOLD`）触发按需压缩（转黄），超 **45k**（`L3_TOKEN_THRESHOLD`）转 planner 归纳（转红）。水位取的是 mlx 返回的真实 `prompt_tokens`，不是消息条数估算。

告警区里最该被看见的是 `flag 被拒`——那是反假阳性闸拦下了一个没在任何工具输出里出现过的 flag。

## 已知限制

- **暂停在 planner 执行中无法立即生效**：planner 是一次 `timeout=600` 的 LLM 调用、中间无循环，暂停会在调用结束后生效。UI 会提示这一点。
- **暂停很久后恢复，首步会慢**：mlx 的 prompt cache 槽位有限，暂停期间可能被挤掉，恢复后要重算整个 prompt。
- **默认只允许 1 个活跃 run**：并行会抢 mlx 缓存 + IDA worker 内存（每个几百 MB）。启动第二个会返回 409，带 `force=true` 可强制。
- **不做文件上传**：题面 `description.md` 要在二进制同级目录（向上找 6 层），所以用服务端目录浏览选题，而不是上传单文件。
- **批量评测不在本界面**：用 `scripts/eval.py`。
- **命令行起的 run，Web 探测不到它活着**：`status()` 靠 `logs/<run_id>.ctl` 里的 pid 判活，而那个文件是 `runner.start` 写的。想让 Web 观察一个手工起的 run，得自己补一句 `ctl.write_state(run_id, "running", pid=<pid>)`。

## 调试时的坑

**手工起 agent 调试时不要用 `conda run` 包装**，否则 `SIGTERM` 打不到 python 进程：

```bash
# ✗ 信号会打给 conda run 这层 wrapper,python 子进程收不到 → 不会优雅退出、不输出 __RESULT__
conda run -n antirev python tests/fixtures/fake_agent.py foo 80 1.5 &
kill -TERM $(pgrep -f fake_agent | head -1)

# ✓ 直接用环境里的解释器(runner.start_script 内部走的就是 sys.executable,没有这层包装)
/Users/bytedance/miniconda3/envs/antirev/bin/python tests/fixtures/fake_agent.py foo 80 1.5 &
```

实测对比：经 `conda run` 起的进程被停止后 stdout 里**没有** `__RESULT__`；`runner.start_script` 起的进程 `stop()` 返回 `{'stopped': 'graceful'}`、耗时 0.3s、`result_of()` 拿到 `{"status": "stopped", "error": "收到 SIGTERM"}`。

## 依赖

`fastapi` + `uvicorn`（已在 `requirements-main.txt`，wheel 已备进 `wheelhouse/` 供赛场离线安装）。前端零构建，不需要 node。

## 详细设计

- 设计：`docs/superpowers/specs/2026-07-27-antirev-web-console-design.md`
- 实施计划：`docs/superpowers/plans/2026-07-27-antirev-web-console.md`

（这两份文档在 `.gitignore` 里，只在本地磁盘——仓库只跟踪 `antirev/` 引擎代码。）
