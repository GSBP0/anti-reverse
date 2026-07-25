# 上下文管理 — 待修复问题清单

> 状态：待修复（依据代码审查 + 评测日志实证）  
> 范围：`antirev/memory/context.py`、`antirev/memory/store.py`、`antirev/react_executor.py`、`antirev/graph/nodes.py`  
> 相关设计：`docs/context.md`、`plan1.md` §6、`Agents.md`  
> 实证日志：`logs/eval_r5_5985.*`、`logs/eval_r10_2000.*`、`logs/eval_r5_3790.*`、`logs/FAILURE_ANALYSIS_top10.md`  
> 更新日期：2026-07-21

---

## 0. 一句话问题画像

当前上下文管理**擅长记住「碰过什么工件」**（函数、字节、工具名），**不擅长记住「得出过什么结论、排除过什么路、差一步成功的线索是什么」**。

| 进度类型 | 是否概括住 |
|----------|------------|
| 查过哪些函数 / 读过哪些字节 | ✅ 台账 |
| 算法理解 / 排除路径 / 半截正确解 | ❌ 靠近窗或易错 summary |
| 失败脚本差异 / traceback | ❌ 被 slim + digest 抹平 |

工具层事实（SQLite）往往正确，**对话记忆是碎的，叙事记忆是漂的**。

---

## 1. 分层架构回顾（便于对照缺陷）

| 层 | 内容 | 位置 | 生命周期 |
|----|------|------|----------|
| Working Memory | 目标 + 事实 + 用户 hint + 结构化台账 | 每步 messages 置顶 | 常驻 |
| 结构化台账 | `func_map` / `reads` / `attempts` / `scans` | 嵌在 WM | 常驻、按 key 去重 |
| 历史窗口 | 最近 `window`（默认 4）步 ACTION/OBS | 消息尾部 | 滑动 |
| 外部记忆 | 工具全文 + 缓存 | SQLite `artifacts` | 永久，可 `recall` |

拼装：`[system] + [task/Plan + WM] + [最近 window 步]`。

---

## 2. 待修复项（按优先级）

### P0-1. 语义 Working Memory / `facts` 层空转

| 字段 | 内容 |
|------|------|
| **现象** | `ContextManager.facts` / `add_fact` 存在，但全项目无调用方；`store.facts` 表几乎恒为空。WM 实际 ≈ goal + 台账，没有「已确认 / 已排除 / 下一步意图」。 |
| **设计落差** | `plan1.md` §6.1 期望：`已确认事实`、`已排除`、`关键地址`、`上一步结论`、`下一步意图`。 |
| **实证** | `eval_r5_5985`：密钥/密文/半截 `NSSCTF{0d6f90ac-...}` 均出现过，但重建台账 `facts=[]`；模型不知道「标准 RC4 已失败」「半截 flag 含义」。 |
| **后果** | 窗口滑出后理解断层；跨轮只能靠易错 summary；重复试同一错误解法。 |
| **修复方向** | 每步规则或小 prompt 自动沉淀 1–3 条 facts（算法名、关键地址+长度、已排除 endian/标准实现、半截 flag）；`working_memory_block` 强制渲染；summary 只能引用 facts 中的数字/hex，禁止自由改写。 |
| **状态** | ⬜ 待修 |

---

### P0-2. 无逐步 rolling summarization，中程语义记忆缺失

| 字段 | 内容 |
|------|------|
| **现象** | 设计 §6.2：每步把 thought/action/obs 压成一两句写入 WM 再丢原文。实现只有**规则台账 + 固定 window**，轮内无 LLM/规则逐步摘要。 |
| **实证** | 5985：步 3 decompile main 后几步写脚本时，main 伪代码已不在窗口；台账只剩签名行，不够抄逆运算。 |
| **后果** | 「理解进度」依赖近窗原文；近窗一滑 → 只能再 decompile / 忘记用 `recall`。 |
| **修复方向** | 每步追加 `step_conclusion`（1–3 句）；或超阈值时批量摘要更早步骤；与 P0-1 facts 合并。 |
| **状态** | ⬜ 待修 |

---

### P0-3. `window=4` 过粗，算法细节过早滑出

| 字段 | 内容 |
|------|------|
| **现象** | 全局固定 `window=4`，不区分 decompile（信息量大）与 analyze（信息量小）。 |
| **实证** | 失败分析：65% 失败 run `run_python=0`；反编译占工具调用 61%；45 个 run 同址 decompile ≥3 次——与「细节只在近窗存活 4 步、台账太瘦」强相关。 |
| **后果** | 重复反编译；「看懂了却不动手」被机制放大。 |
| **修复方向** | 自适应 window（大 obs 后扩大保留 / 按 token 预算）；对「含伪代码的最近一次 decompile」单独钉住不滑出，直到 `run_python` 成功或用户换函数。 |
| **状态** | ⬜ 待修 |

---

### P0-4. 跨轮 `round_summary` 不可校验、互相打架

| 字段 | 内容 |
|------|------|
| **现象** | summary 仅失败轮末写一次，模型对着上下文**重新叙事**，不从台账/DB 校验。Planner 将其标为「最关键输入」。 |
| **实证** | `eval_r5_5985` 五轮 summary 对密文长度：32 → 32 → 写半段 hex 仍标 32 → **20** → **25**；算法在「标准 RC4 / 魔改」间摇摆。DB 真实：`0x404160` 为 32B 完整 hex。 |
| **后果** | Planner 按错误长度/算法规划；replan 不收敛（见 3790 TEA↔XOR↔XTEA↔XXTEA 横跳）。 |
| **修复方向** | summary 模板强制填结构化字段，且与 `reads`/`facts` 交叉校验；冲突时以 SQLite 为准并在 prompt 中标注「已核实」；保留多轮 summary 时做 diff/合并而非只塞最后一轮。 |
| **状态** | ⬜ 待修 |

---

### P0-5. 历史 `run_python` 脚本被抹掉，失败不可诊断

| 字段 | 内容 |
|------|------|
| **现象** | `_slim_run_python`：窗口内非最近一次的 `code` 换成占位；`attempts` digest 多为 `rc=1 stdout= [有stderr]`，无 traceback 要点。 |
| **实证** | 5985 步 11 ValueError 越界、步 12 半截 flag；后续窗口/台账看不到步 11 与步 12 的代码差，又出现步 16/17 同类半截输出。 |
| **后果** | 同错重试；无法从「哪一行错」改进。 |
| **修复方向** | 失败脚本保留：stderr 首尾 N 行 + code hash + 一行 diff 摘要进 facts/attempts；或最近 K 次失败脚本不 slim。 |
| **状态** | ⬜ 待修 |

---

## 3. 待修复项（P1）

### P1-1. 台账「空间有界」未落地，attempts 无限膨胀

| 字段 | 内容 |
|------|------|
| **现象** | 文档写函数图留 50、尝试留 20；代码对 `func_map`/`reads`/`attempts` **无截断**。 |
| **实证** | 5985 重建：`attempts=47`，多行相同乱码 stdout 全量进 WM（~5.4k 字符常驻）。 |
| **后果** | 有效信号被淹没；WM 每步变大 → KV 更难复用；挤占近窗预算。 |
| **修复方向** | 硬截断 + 折叠：`标准RC4×4→同一乱码` 合成一条；保留最近 N + 含 flag-like / 唯一错误类型。 |
| **状态** | ⬜ 待修 |

---

### P1-2. 台账字段信息密度不足（索引 ≠ 可解题状态）

| 字段 | 内容 |
|------|------|
| **现象** | `func_map` 仅首行签名 + callees/refs，**不存**伪代码要点、关键常量、比较目标、memcmp 长度。 |
| **实证** | 5985 ledger：`main ... | refs 0x404040,0x404160` —— 知道引用了地址，不知「0x404160 是 32B 密文 v1」。 |
| **后果** | 台账防重复查询有用，据台账直接写逆运算不够；仍依赖 recall/再 decompile。 |
| **修复方向** | decompile 后规则提取：循环/异或/TEA/RC4 关键词、常量、memcmp size；写入 `func_map[key].notes` 或 facts。 |
| **状态** | ⬜ 待修 |

---

### P1-3. Planner 侧上下文仍可能爆，replan 转嫁而非消化

| 字段 | 内容 |
|------|------|
| **现象** | replan 注入：summary + ledger + **全量 decompile** + 完整 trace；`plan_max` 随 prompt 膨胀被压扁。 |
| **实证** | `eval_r10_2000`：单步 `ida_disasm` obs≈61k 字符×多次 → step10 `context_limit_replan` approx_tokens=**65423**，ctx_chars≈196270。 |
| **后果** | Executor 熔断后 Planner 输入更大；Plan 变短变糊；Executor 再从瘦 Plan 起步。 |
| **修复方向** | Planner 输入分级：默认 summary+ledger+**精选** decompile；仅卡死时灌全量；disasm 进窗口前强制更狠的 clip；同地址 disasm 不重复进窗。 |
| **状态** | ⬜ 待修 |

---

### P1-4. Planner 方向摇摆 / replan 摧毁已有正确路径

| 字段 | 内容 |
|------|------|
| **现象** | 每轮 summary 强调点不同 + 无「已确认算法」facts → Planner 重新选题型。 |
| **实证** | `eval_r5_3790` 约 12 轮：TEA → XOR → XTEA → XXTEA+XOR → 又回 XOR → TEA 变种…；失败分析 B 类「replan 摧毁 executor 已推出的正确解法」。 |
| **后果** | 长跑不收敛；预算耗在换题型而非加深。 |
| **修复方向** | Plan 必须声明 `confirmed` vs `hypothesis`；replan 默认继承 confirmed；禁止无新证据时改算法家族。 |
| **状态** | ⬜ 待修 |

---

### P1-5. 消息布局与 KV cache 最优方案不一致

| 字段 | 内容 |
|------|------|
| **现象** | 设计要求易变 WM 靠后以利前缀缓存。实现：`system | task+WM | window`，WM 每步变则其后整段重 prefill。 |
| **后果** | 本地 MLX 延迟恶化；只稳定了 system。 |
| **修复方向** | 改为 `system | plan(稳定) | window | WM(最新)` 或「本步 delta 放尾」；测量 TPS 对比。 |
| **状态** | ⬜ 待修 |

---

### P1-6. 同址反复 decompile：有缓存、无决策记忆

| 字段 | 内容 |
|------|------|
| **现象** | SQLite `find_cached` 让重复 IDA 调用很快返回，但上下文不强制「已读过、结论是 X、禁止再读」。 |
| **实证** | 3790 类：`ida_decompile` 158 次 / 仅 16 地址；`0x414b00×22` 等。 |
| **后果** | 省 CPU 不省步数/决策；配合 stuck 易冤杀。 |
| **修复方向** | 连续/累计同 `(tool,归一化地址)` 达阈值 → 硬拦截并注入「据台账 notes 动手」；与现有复读熔断对齐到地址级。 |
| **状态** | ⬜ 待修 |

---

## 4. 待修复项（P2）

### P2-1. 压缩策略内部张力（「不裁剪」vs 省上下文）

| 字段 | 内容 |
|------|------|
| **现象** | 注释同时强调完整 THOUGHT/反编译 与 `_clip_big`/artifact/slim；预算花在近窗厚原文，中间档「算法级结论」缺失。 |
| **修复方向** | 明确优先级：facts/结论 > 最近一次关键伪代码 > 历史脚本摘要 > 重复 disasm；写进 `docs/context.md` 并与代码一致。 |
| **状态** | ⬜ 待修 |

---

### P2-2. `exchanges` 列表只截断渲染、不截断存储

| 字段 | 内容 |
|------|------|
| **现象** | `build_messages` 取 `[-window:]`，但 `self.exchanges` 无限 append。 |
| **后果** | 长跑内存上涨；与「有界上下文」不一致。 |
| **修复方向** | 保留最近 `window*2` 或按步归档到 store。 |
| **状态** | ⬜ 待修 |

---

### P2-3. 文档 / 测试 / 实现漂移

| 字段 | 内容 |
|------|------|
| **现象** | `docs/context.md` 写 max_tokens=2048、台账截断 50/20；代码 executor `max_tokens=6144`、无截断。`test_context_window_bounded` 期望 WM 含 `步1:`/`步7:`，实现 WM 不渲染 `step_notes`，`ida_read_bytes` 进 `reads` 而非 `attempts` 的步号格式。 |
| **后果** | 后续改动无单一真相源；测试可能误导。 |
| **修复方向** | 统一文档参数表；修测试断言对齐真实 WM 语义。 |
| **状态** | ⬜ 待修 |

---

### P2-4. 与 stuck / 进展判据叠加的负反馈链

| 字段 | 内容 |
|------|------|
| **现象** | `_is_progress` 很严；台账不长且窗口丢理解 → 重复探索 `grew=False` → stuck。 |
| **实证** | 失败分析 M 类：慢生成 × stuck；7067 等「方向对、动手前被杀」。 |
| **修复方向** | 上下文侧：facts 含「已理解算法」时延长 stuck 或算软进展；判据侧：扣除生成等待 / 按有效工具步数（可与 FAILURE_ANALYSIS 杠杆合并）。 |
| **状态** | ⬜ 待修 |

---

### P2-5. 大 disasm/花指令区进窗策略过弱

| 字段 | 内容 |
|------|------|
| **现象** | `_clip_big` 默认约 8k，花指令题仍可达数万字符；同址多次进窗叠加爆 64k。 |
| **实证** | `eval_r10_2000` 连续 61k 级 disasm obs → context_limit。 |
| **修复方向** | 花指令/超大 disasm：默认只留头尾 + artifact id，禁止同 addr 二次全文进窗；引导 `solve_stateless_transform` / emulate。 |
| **状态** | ⬜ 待修 |

---

## 5. 负反馈故事（修复时回归用）

### 5.1 5985（RC4 / 语义失忆）

```text
① 反编译 main，看懂调用链          ← 细节在窗口
② 读密钥/密文进台账                 ← 有 hex，无「已确认」
③ 标准 RC4 → 乱码 ×4                ← attempts 不记「已排除」
④ 窗口滑出 main 伪代码               ← 理解断层
⑤ 魔改脚本偶发半截 flag              ← 稍后只剩 digest
⑥ 再 decompile / 再乱码              ← 重复劳动
⑦ 轮末 summary 把 32B 写成 20B/25B   ← 跨轮污染
⑧ Planner 按错误长度规划             ← replan 不收敛
⑨ attempts 膨胀、stuck               ← 失败
```

**回归验收**：facts 含 cipher@addr 32B + 已排除标准 RC4；summary 不得改写该长度；半截 flag 进 facts。

### 5.2 2000（花指令 / 上下文顶爆）

```text
短步数内多次 61k 级 ida_disasm → ~65k token 熔断
→ replan 灌全量证据 → Planner 更重 → 未真正消化
```

**回归验收**：同址 disasm 第二次起仅 artifact 引用；step 内 token 远低于 51k 熔断线。

### 5.3 3790（Planner 横跳）

```text
无 confirmed facts → 每轮 summary 换焦点
→ Plan 在 TEA/XOR/XTEA/XXTEA 间横跳 → 不收敛
```

**回归验收**：连续 replan 在无新工具证据时算法家族不变。

---

## 6. 建议修复顺序（实施路线）

| 阶段 | 项 | 目标 |
|------|-----|------|
| **A. 钉死事实** | P0-1, P0-4, P1-2 | 轮内/跨轮数字与算法结论可校验 |
| **B. 保留可诊断失败** | P0-5, P1-1 | 同错不重演、台账可扫 |
| **C. 留住算法细节** | P0-2, P0-3, P2-5 | 少重复 decompile、少顶窗 |
| **D. 跨轮收敛** | P1-3, P1-4, P1-6 | replan 继承 confirmed、输入分级 |
| **E. 性能与卫生** | P1-5, P2-2, P2-3, P2-1, P2-4 | KV、文档、测试、stuck 协同 |

---

## 7. 相关代码锚点

| 模块 | 路径 | 职责 |
|------|------|------|
| ContextManager | `antirev/memory/context.py` | WM、台账、窗口、`build_messages`、`load_prior`、`_clip_big`、`_slim_run_python` |
| MemoryStore | `antirev/memory/store.py` | artifacts / facts / 缓存 / contains |
| ReactExecutor | `antirev/react_executor.py` | window、summary、stuck、context_limit、复读熔断、`_compress_output` |
| Planner/Executor 节点 | `antirev/graph/nodes.py` | replan 证据包、plan_max |
| 文档 | `docs/context.md` | 分层说明（需与实现同步） |

---

## 8. 状态图例

- ⬜ 待修  
- 🔧 进行中  
- ✅ 已修（请在 PR/提交中回写日期与验证日志）  
- ❌ 放弃（注明原因）

---

## 9. 修订记录

| 日期 | 说明 |
|------|------|
| 2026-07-21 | 初版：汇总上下文管理全部已知缺点与实证，形成待修复清单 |
