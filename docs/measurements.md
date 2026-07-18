# antiReverse 实测记录（§14 step 0 的两个"开工先钉死"数）

> 环境:MacBook Pro M4 / 48GB;IDA Professional 9.3;模型 qwen3.6-35b-a3b-6bit @ mlx_lm.server(127.0.0.1:7777)。
> 日期:2026-07-18。

## 1. idalib 离线 dry-run（§9.2 一票否决项）— ✅ 通过

- brew Python 3.14.3 下 `import idapro` 成功(IDA 9.3 的 IDAPython 是 cp314 ABI,必须用 3.14)。
- 对手工样本 `flagcheck` open_database → auto_wait → add_func → **hexrays 反编译成功**,输出完整伪代码。
- 结论:idalib 后端离线可用,走 idalib(不退回 idat64 batch)。IDA worker 用 py3.14 独立子进程,与主环境(py3.12 + angr)进程隔离。

## 2. 单步端到端延迟（§7.4）— ✅ 实测

### 模型单步(mlx_lm.server)
| 场景 | 输入 tok | 延迟 | 输出 tok |
|---|---|---|---|
| 关思考,小上下文 | ~28 | **0.58s** | 14 |
| 关思考,大上下文 | ~3231 | **4.53s** | 7 |
| 开思考,小上下文 | ~28 | 4.00s | 200(含思考) |

- **关思考(`chat_template_kwargs.enable_thinking=false`)是头号延迟杠杆**:同等小上下文 0.58s vs 4.0s,~7–16x。落地 §3.3「Executor 不开 thinking」。
- prefill 随上下文线性增长(~3.2k tok ≈ 4.5s),印证 §6.4「缓存友好排布 / 控制上下文规模」的必要性。

### 厚工具单次
| 工具 | 耗时 |
|---|---|
| solve_locate(IDA 起停 + pwntools + xref) | ~2.4s |
| solve_angr(子进程符号执行,本样本) | ~8–12s |
| solve_verify(angr 具体执行) | ~3.8s |
| ida_decompile(worker 已常驻时) | <1s |

### 每题步数上限反推
- 典型单步 ≈ 模型(关思考)~0.6–4.5s + 工具~3–12s ≈ **5–15s/步**。
- 20min/题预算 → **约 80–140 步**。
- 结论:**§7.4 的担忧被缓解**——原怕 30–60s/步(只够 20–40 步)。关思考后模型极快,瓶颈是工具(IDA/angr)而非模型 prefill。真正要压的是工具往返次数(厚工具 + 确定性预处理),不是模型延迟。

## 3. 模型端点事实（钉死 §1.2 / §12）

- 运行时:**mlx_lm.server**(MLX,正合 §7.2 推荐),OpenAI 兼容。
- 型号确认:**35B**-a3b-6bit(非 30B),印证 §7.1 的 ~29GB 权重内存账。
- **不支持原生 function-calling**:`tools` 不解析成 `tool_calls`,只把工具调用当文本返回 → 必须走 §12 显式 ReAct 文本协议(已实现 react_executor)。
- 支持 `chat_template_kwargs` 透传 chat template → 用它关思考。
- 响应中思考在 `message.reasoning`、答案在 `message.content`。

## 4. MVP 端到端结果

- **无模型固定流水线**(pipeline_mvp):decompile→locate→angr→verify,4 工具确定性出 flag 并回验 ✅(23 测试通过)。
- **模型驱动 ReAct**(react_executor):35B 本地模型 4 步经工具端到端解出 `flag{unic0rn_x0r}` 并回验 ✅。
