# antiReverse

> 一个用于**线下 CTF 比赛**的逆向工程 Agent 框架。仅打逆向题目;线下比赛不准联网,所有工具、模型、依赖必须**提前在本地准备完毕**,运行期完全离线。

---

## 1. 背景与约束

### 1.1 本机配置
| 项 | 值 |
|---|---|
| 机型 | MacBook Pro Max (Apple Silicon) |
| 芯片 | M4 |
| 内存 | 48 GB 统一内存 |
| 存储 | 512 GB |

### 1.2 模型
| 项 | 值 |
|---|---|
| 本地模型 | Qwen3.6-35B-A3B(MoE,3B 激活) |
| 量化 | 6-bit |
| 上下文 | 64k(**为上限,非目标**,见 §7) |
| API 端点 | `http://127.0.0.1:7777`(OpenAI 兼容) |

> ⚠️ **型号待钉死**:公开型号是 `Qwen3-30B-A3B`(30B 总参 / ~3B 激活),并无 "Qwen3.6-35B-A3B" 这一款。§7 的内存账取决于确切参数量,开工前先确认真实权重规模(30B 还是 35B),否则内存预算会偏。

### 1.3 硬约束(推导自上面两项,贯穿全文)
- **内存是瓶颈,不是速度**。A3B 只激活 3B,推理很快;但 6-bit 权重驻留约 **29 GB**,加 macOS ~8 GB,**只剩 ~11 GB** 给 KV cache + 全部工具。
- **完全离线**。运行期无法 `pip install`、无法下载 IDA 插件、无法访问 libc-database / 在线沙箱。一切前置。
- **敌意二进制**。CTF 样本可能畸形/带反调试/触发崩溃,工具进程随时可能挂 —— 需要隔离与超时。

---

## 2. 核心设计原则(先立原则,再谈实现)

这些原则是前期反复推演出来的,决定了下面所有技术选择。**违背原则的"优化"通常是负优化。**

1. **屏蔽弱模型直面的复杂度。** 35B-A3B 不是前沿云端模型,别让它读原始反汇编硬推。它的职责收窄为:**识别模式 + 决策路由**,真正的计算外包给确定性工具。
2. **求解外包 > 模型硬算。** 能自动化的部分,核心是**约束求解 + CPU 级模拟(z3/angr/unicorn)**,不是反编译器,更不是让 LLM 心算。这是本框架**最该重投入**的一层。但要清醒:**符号执行不是银弹**——现代混淆题(VM、重循环、哈希校验)常常就是冲着干掉 angr 设计的,且它在 ~5GB 内存头寸下容易状态爆炸。把 angr 定位成"适用时很省力的一条路",而不是框架价值的支柱;真正决定解题率的,往往是"能不能用确定性工具帮模型看懂逻辑 + 自动喂对参数"(见 §5.2)。
3. **厚工具 > 薄工具。** 不暴露底层原语让模型编排(它会跑飞),而是把逆向推理封进任务级工具(如 `solve_flag_with_angr`),模型只在高层调用。
4. **检索 + 压缩,绝不 dump。** 工具只返回**紧凑切片**(一个函数的伪代码、几条 xref),全量分析存外部库按需取。上下文里永远只有"当前需要的一小块"。
5. **给模型让内存。** RE 工具链是配角,内存的头号消耗者是模型本身。工具**串行使用内存,不并发抢占**;IDA/angr/VM 用完即释放。
6. **确定性优先,少调模型。** 能用确定性手段(抽字符串、angr 自动试解、packer 检测)解决的,先跑,不唤醒模型。模型是"卡住时的升级通道"。

---

## 3. 整体架构

```
                    ┌─────────────────────────────────────────┐
                    │         LangGraph 编排层 (StateGraph)      │
                    │   全局状态: 题目信息 / Plan / 进度 / flag    │
                    └─────────────────────────────────────────┘
                          │                          ▲
              产出 Plan.md │                          │ 卡住时请求重规划
                          ▼                          │
        ┌──────────────────────┐          ┌──────────────────────┐
        │   Planner (thinking)  │          │   Executor (ReAct)    │
        │  收集信息→分类→规划     │─Plan.md─▶│  按 Plan 逐步执行       │
        │  产出结构化 Plan.md     │          │  + 上下文管理 (§6)     │
        └──────────────────────┘          └──────────┬───────────┘
                                                      │ 调用工具
                          ┌───────────────────────────┼───────────────────────────┐
                          ▼                           ▼                           ▼
                 ┌─────────────────┐        ┌─────────────────┐         ┌─────────────────┐
                 │  IDA 静态工具集   │        │  求解工具集       │         │  辅助/terminal   │
                 │ (headless idalib)│        │ angr/z3/unicorn │         │ 分析 + 命令执行   │
                 └─────────────────┘        └─────────────────┘         └─────────────────┘
                          │                           │                           │
                          ▼                           ▼                           ▼
                 ┌───────────────────────────────────────────────────────────────────┐
                 │        外部记忆层 (SQLite): 全量函数/xref/字符串/中间结论             │
                 └───────────────────────────────────────────────────────────────────┘
```

### 3.1 为什么用 LangGraph 而不是裸 LangChain AgentExecutor

你指定了 LangChain,而在 LangChain 生态里,**LangGraph 才是为"有状态 + 多 Agent + 需要精细上下文/回路控制"场景设计的正确工具**。理由:
- **显式状态图**:你的双 Agent 有明确的状态流转(收集→规划→执行→卡住→重规划→验证),LangGraph 的 `StateGraph` 天然表达这个,比 AgentExecutor 的黑盒循环可控得多。
- **回路与条件边**:Executor 卡住时回到 Planner 重规划,用条件边(conditional edge)一行表达。
- **持久化 / 断点**:LangGraph 的 checkpointer 让你能保存/恢复状态、逐步单步调试 Agent —— 开发期极有用。
- **上下文完全可控**:每个节点收发什么进上下文由你定,正好实现原则 4 的"绝不 dump"。

> AgentExecutor 那套隐式 ReAct 循环把上下文管理藏起来了,而你恰恰需要**手动掌控上下文**,所以用 LangGraph。

### 3.2 Planner(规划 Agent)

- **模式**:thinking(充分推理)。⚠️ 弱模型的长 thinking 未必增益却确定烧延迟(见 §7.4 延迟账),开工后实测"开/关 thinking"对分类质量的影响,再决定是否常开。
- **输入**:题目文件路径 + 一批**确定性预分析结果**(见 §5.3,`file`/DIE/strings/binwalk 的输出),而不是让它自己一步步跑命令收集。**先把廉价信息喂饱它,减少往返。**
- **职责**:
  1. **题型分类**(见 §8):flag 校验函数 / VM 混淆 / 加壳 / 加密算法 / 反调试 / …
  2. 产出 **`Plan.md`**:结构化的分步计划,每步标注**目标 + 建议工具 + 成功判据**。
- **`Plan.md` 建议模板**:
  ```markdown
  # Plan: <题目名>
  ## 题型判断
  - 主类型: <flag校验 / VM / 加壳 / 加密 / ...>
  - 架构: <x86-64 / ARM64 / MIPS / ...>
  - 关键观察: <保护措施 / 可疑函数 / 字符串线索>
  ## 分步计划
  - [ ] Step 1: <目标> | 工具: <ida.decompile / solve_with_angr / ...> | 判据: <如何算完成>
  - [ ] Step 2: ...
  ## flag 格式
  - 预期: flag{...} (或题目指定)
  ```

### 3.3 Executor(执行 Agent,ReAct)

- **模式**:ReAct(Reason + Act 循环)。⚠️ **不开模型内置 thinking**:ReAct 的显式 Thought 步已经承担推理,再叠 thinking 只会翻倍 token 与延迟(§7.4),且弱模型长思容易跑飞——Executor 的"思考"一律走 ReAct 的 Thought,不走 thinking 模式。
- **初始 prompt** = 系统 prompt + `Plan.md`。
- **工具**:IDA 静态工具集、求解工具集、辅助分析工具、terminal(见 §5)。
- **核心难点 = 上下文管理**(见 §6):每一步都必须把"当前全部进度"压缩进一个可控的 working memory,让 Agent 能顺着上一步继续,直到达成 `Plan.md` 的目标。
- **终止条件**:
  - **成功**:拿到候选 flag 后,**不能只靠正则格式校验**——格式对 ≠ 是真 flag(尤其 angr 求出的输入可能只是"能到达目标地址"而非真解)。成功判据应为:**用 unicorn/模拟把候选喂回二进制自己的校验函数,确认真的走到 accept 分支**(见 §5.2 `solve.verify`);无法回验时才退回格式校验,并在日志标注"未经二进制自验,存在假阳性"。
  - **重规划**:连续 N 步无进展 / Plan 步骤被证伪 → 回到 Planner(带上已知信息)重新规划。
  - **超预算**:单题超过时间预算(见 §11)→ 记录现状,标记失败,换下一题。

### 3.4 关键补充:Planner ↔ Executor 反馈回路

你原计划是 "Planner 产出 Plan.md,Executor 一路执行到底"。**单次规划在 CTF 里经常失败**(初始判断错、卡在死路)。必须加回路:
- Executor 维护一个 `stuck_counter`;无进展累积到阈值,发出 `request_replan` 信号。
- LangGraph 条件边把控制权交回 Planner,Planner 拿到**Executor 积累的新证据**(已确认/已排除的东西)重新规划,更新 `Plan.md`。
- 防死循环:限制重规划次数(如 ≤3),超了走"超预算"分支。

---

## 4. IDA 工具选型决策

你给了三个候选,让我选一个或结合精华自研。**结论:以 `DennyDai/headless-ida` 为引擎,在其上自研一层"薄封装的厚工具";`mrexodia/ida-pro-mcp` 仅开发期用。** 逐个分析:

| 候选 | 形态 | 语言 | 评价 |
|---|---|---|---|
| `mrexodia/ida-pro-mcp` | GUI + MCP | Python | GUI 吃 1–3GB 内存,与模型抢 RAM;可视化对**自动执行**无价值。**保留作开发期调试**(看 Agent 在读哪、手动纠偏),不进生产。 |
| `blacktop/ida-mcp-rs` | headless + MCP | Rust | 快,基于 idalib。但给 Python/LangChain 栈引入一个 Rust 组件 + MCP 层;文档偏 Windows(`ida.dll`/`idalib.dll`)。离线单机场景,MCP 的远程/隔离优势用不满,徒增复杂度。 |
| `DennyDai/headless-ida` | headless | **Python** | **最契合**:Python 原生,直接在无界面进程里跑 IDAPython;支持 idalib 后端(给 idalib 路径替代 `idat64`);自带 `headless-ida-server` 模式可做**进程隔离**。与 LangChain 无缝,厚工具想怎么封就怎么封。 |

### 为什么"吸收精华自研"而不是直接套 MCP 框架

1. **你需要 CTF 专用的厚工具,不是通用 MCP 原语。** 现成 MCP 服务暴露的是 `decompile` / `get_xrefs` 这类通用操作,且倾向返回完整输出 —— 这**违背原则 4(绝不 dump)**。你要的是"返回压缩切片、面向你上下文预算"的定制工具。
2. **单机离线,MCP 的跨进程协议开销不划算。** MCP 的价值在远程/隔离;你在一台机器上跑,隔离用子进程 + 超时即可实现,不必背 MCP 协议层。
3. **进程隔离仍要做。** 敌意样本会崩 IDA。用 `headless-ida` 的 **server 模式**(或自己把 idalib 跑在受管子进程里),单个样本搞崩分析进程时 Agent 主循环还活着。

> 迁移成本低:`headless-ida` 就是让你 `from headless_ida import HeadlessIda; HeadlessIda(idat_path, binary); import idautils ...`,你在这之上写 LangChain `@tool` 即可。

> **前置校验**:idalib 是 IDA **9.0+** 才有的后端。若你的 IDA 是 8.x,idalib 路径不存在,`headless-ida` 需退回 `idat64` batch 模式跑 IDAPython(另一条代码路径)。开工前先确认 IDA 大版本(见 §9.2)。

---

## 5. 工具层设计

### 5.1 IDA 静态工具集(基于 headless-ida / idalib)

全部遵循**返回压缩切片**原则。建议工具:

| 工具 | 作用 | 输出控制 |
|---|---|---|
| `ida.list_functions(filter?)` | 列函数(可按名/大小/是否库函数过滤) | 只返回名+地址+大小,不返回体 |
| `ida.decompile(name_or_addr)` | 反编译**单个**函数 | 一次一个;超长则附"函数过大"提示,建议分块或转 angr |
| `ida.disasm(addr, count)` | 取一段反汇编 | 限制条数 |
| `ida.xrefs_to(addr)` / `xrefs_from(addr)` | 交叉引用 | 只返回地址+所属函数名 |
| `ida.strings(filter?)` | 字符串(可正则过滤) | 优先过滤,避免全量 |
| `ida.imports()` / `exports()` | 导入导出表 | 用于识别加密/系统调用线索 |
| `ida.get_bytes(addr, size)` | 读原始字节 | 十六进制 |
| `ida.decompile_to_db(name)` | 反编译并**存入外部记忆层**,返回摘要 | 全文进 SQLite,上下文只回摘要 |

### 5.2 求解工具集(⭐ 本框架核心,原计划缺失)

**这是 rev 自动化里能确定性化的部分。** 全部做成厚工具,模型只提供高层参数:

| 工具 | 作用 | 关键参数 |
|---|---|---|
| `solve.locate_targets(binary)` | **确定性推导 angr 的 find/avoid**:抽 `"Correct"/"Wrong"/"Success"/"Nope"` 等字符串 → 取 xref → 反推成功/失败分支地址,直接喂给 `solve.angr`。**别让弱模型猜地址**(见下方漏洞说明) | 内置常见成功/失败关键词表,可扩展 |
| `solve.angr(binary, find, avoid?, stdin_len?, hooks?)` | 符号执行自动求 flag:探索到 `find` 地址、避开 `avoid`,约束求解出满足的输入 | 封装完整 angr 流程(建 project、造 state、explore、约束求解),内置**状态上限 + 超时 + LAZY_SOLVES/veritesting** 防路径爆炸 |
| `solve.z3(constraints_desc)` | 当模型已从伪代码读懂校验逻辑(如逐字节异或再比较),把逻辑转 z3 约束求解 | 提供**模板脚手架**让模型填空,而非从零写 |
| `solve.unicorn(binary, start, end, regs?, mem?)` | CPU 级模拟执行一段代码(解密循环 / VM handler),取运行结果,不启动整个程序 | 架构无关,天然沙箱 |
| `solve.brute(func_emulate, space)` | 小空间爆破(逐字符判定型校验),用 unicorn 模拟单函数 | 限制空间大小 |
| `solve.verify(binary, check_addr, candidate)` | **候选回验**:用 unicorn 把候选 flag 喂回二进制自己的校验函数,确认真的走到 accept 分支,这是 §3.3 的强成功判据 | 无法隔离校验函数时降级为格式校验并标注风险 |

> **⚠️ "外包给工具"有个没堵上的漏洞**:`solve.z3` 要模型**读懂伪代码并翻译成约束**、`solve.angr` 要**判断哪个地址是"成功"**——这两处恰恰是本框架想避免的那种推理。对策:能确定性推导的就别让模型猜——`solve.locate_targets` 自动给出 find/avoid,`solve.verify` 自动确认候选,把模型职责真正压回"高层路由"。
>
> **架构覆盖**:你有全架构 IDA license,反编译由 IDA 顶(不再依赖 Ghidra)。`solve.angr` / `solve.unicorn` 在此定位为**求解**引擎,而非架构兜底——符号执行不是银弹,现代混淆题常打崩它,别当框架支柱(见 §2 原则 2)。

### 5.3 辅助分析工具(确定性预处理,喂给 Planner)

**这些在 Planner 规划前就跑,把廉价信息喂饱它(原则 6):**

| 工具 | 作用 |
|---|---|
| `analyze.file_info` | `file` + 基本信息(架构、位数、是否 stripped) |
| `analyze.detect_packer` | Detect-It-Easy (`diec`) 检测加壳/编译器 |
| `analyze.unpack_upx` | UPX 自动脱壳 |
| `analyze.floss` | FLARE FLOSS 提取**混淆字符串**(rev 神器,常直接给线索) |
| `analyze.binwalk` | 嵌入文件/固件分析 |
| `analyze.entropy` | 熵分析,定位加密/压缩段 |

### 5.4 terminal 工具

- 执行本地命令,但**必须**:超时(默认 30s)、在受限工作目录、捕获 stdout/stderr/returncode。
- **边界**:terminal 是"杂项兜底",angr/z3/unicorn/floss **不要**走 terminal 裸调 —— 它们是一等厚工具(§5.2/5.3),这样模型调用更可靠、输出更结构化。terminal 用于临时 `xxd`、`strings`、自定义脚本等。

### 5.5 工具设计三原则(再强调)
1. **输出压缩**:返回结论/切片,不返回大段原文;大段原文进外部记忆层。
2. **厚封装**:把多步逆向逻辑封进一个工具,模型不编排底层。
3. **隔离 + 超时**:每个工具(尤其 IDA、angr)在受管子进程跑,带超时,崩溃不影响主循环。

---

## 6. Executor 上下文管理策略(你 explicitly 要求的重点)

这是 Executor 的成败关键。目标:**让上下文尽量概括当前全部进度,并能让 Agent 顺着上一步继续。** 对一个 64k 上限、3B 激活的模型,这不是优化而是**能不能跑起来的前提**。四层机制:

### 6.1 结构化 Working Memory(每步刷新的"进度状态")

维护一个始终注入上下文的**紧凑状态块**,每步更新,取代"保留全部历史":

```markdown
## 当前进度 (Working Memory)
- 目标 (来自 Plan.md 当前步): <...>
- 已确认事实: <flag 校验在 sub_401080;算法疑似 XOR>
- 已排除: <非 UPX 壳;main 无直接比较>
- 关键地址/符号: {check_fn: 0x401080, key_buf: 0x404050}
- 上一步动作 + 结果摘要: <反编译 sub_401080 → 见异或循环,key 在 0x404050>
- 下一步意图: <用 solve.z3 建异或约束求 flag>
```

**关键:完整的反编译伪代码、长工具输出【不】留在上下文里,只留"结论 + 地址"。** 需要重看某函数时,再用 `ida.decompile` 拉一次(它在外部记忆层有缓存)。

### 6.2 历史压缩(Rolling Summarization)

- ReAct 每完成一步,把该步的 `(thought, action, full_observation)` **压缩成一两句结论**,写入 Working Memory,然后**从上下文丢弃完整原文**。
- 触发式压缩:当上下文 token 数超过阈值(如 40k,**远低于 64k 上限**),批量摘要更早的步骤。
- 用一个便宜的小 prompt 让模型自己做摘要,或规则化提取(工具名 + 关键返回值)。

### 6.3 外部记忆层(SQLite,离线)

- **存全量、上下文只放引用**:所有反编译结果、字符串、xref、中间结论存本地 SQLite。
- 表设计(示例):`functions(addr, name, decompiled_text, summary)`、`strings(addr, value)`、`facts(key, value, step_id)`、`artifacts(type, path)`。
- 工具优先从这里取,避免重复反编译(既省时间又省上下文)。本质是**对二进制做 RAG**。

### 6.4 上下文预算分配(64k 上限内)

| 段 | 预算 | 缓存属性 |
|---|---|---|
| 系统 prompt + 工具定义 + few-shot 示例 | ~5–8k | **稳定**(整局不变) |
| Plan.md(稳定部分) | ~1–2k | **稳定** |
| Working Memory(每步刷新) | ~1–2k | 易变 |
| 当前函数伪代码 / 工具输出 | ~2–5k | 易变 |
| ReAct 近几步(未压缩) | ~5–10k | 易变 |
| **实际常态占用** | **~15–27k** | |

> ⚠️ 工具定义别低估:十几个厚工具的 schema + 每个的 few-shot 示例很容易到 5–8k,不是 3–4k。

**缓存友好的排布(本地推理省延迟的关键,见 §7.4 延迟账)**:上下文必须按 **"稳定前缀在前、易变内容在后"** 排——系统 prompt / 工具定义 / few-shot / Plan.md 稳定段放最前面,让推理运行时(MLX、llama.cpp 都支持前缀 KV 缓存)跨 ReAct step 复用 KV;Working Memory、当前伪代码、最近几步放最后。**若把每步都变的 Working Memory 放在靠前位置,后面整段 KV 缓存全失效,每步都要重新 prefill,延迟翻数倍。** 这是本地推理场景性价比最高的一处优化。

> 结论:**做好 6.1–6.3,实际占用远低于 64k**。64k 是给"偶尔要同时看几个大函数"留的余量,不是常态目标。**若你发现常态就逼近 64k,说明上下文管理没做好 —— 该修这里,不是加窗口。**

---

## 7. 资源 / 内存管理(48GB 的硬账)

### 7.1 内存预算(6-bit 权重)
| 项 | 内存 |
|---|---|
| macOS + 常驻 | ~8 GB |
| Qwen 35B-A3B @ 6bit 权重 | ~29 GB |
| KV cache @ 64k(**需 8-bit KV**) | ~6 GB |
| **剩余给工具** | **~5 GB** |

### 7.2 由此推出的铁律
- **KV cache 必须开 8-bit 量化**。64k 的 fp16 KV(~12GB)在你机器上装不下。8-bit(~6GB)才留得出工具空间,质量损失小。
  - MLX:用其量化 KV 选项;llama.cpp:`--cache-type-k q8_0 --cache-type-v q8_0 -c 65536`。
- **工具串行,不并发**。~5GB 装不下"IDA + angr + VM 同时开"。分阶段:
  - 静态阶段:IDA headless 常驻(~1–3GB)。
  - 求解阶段:跑 angr(~1–4GB)时,**释放非必要 IDA 资源**;给 angr 设**状态上限 + 超时**防内存爆炸。
  - 动态阶段(若需要):headless 调试 VM(~1–2GB),此时不并发 angr。
- **IDA 用完即释放**。分析进程按需起停,不长期驻留占内存。
- **推荐用 MLX 跑模型**(Apple 原生,统一内存效率略优)。

### 7.3 撞墙后路
虽然离线不能远程到云,但可以**在赛场准备第二台机器**跑重工具(angr/IDA),主机专跑模型,两机内网直连。工具层从一开始就抽象成"可换成远程调用",内存不够时切过去。**这是唯一在不牺牲 6-bit 模型质量前提下的扩容路径。**

### 7.4 延迟账(内存之外的另一半成本)
你只算了内存,没算延迟。A3B 出 token 快,但**每个 ReAct step 都要把不断增长的上下文重新 prefill 一遍**,64k 上下文在 M4 上预填可能是几秒到几十秒/步。粗算:若每步(prefill + 生成 + 工具执行)30–60 秒,§11 的"每题 20 分钟"只够 **~20–40 步**——对难题很紧。三条应对:
- **实测钉死单步耗时**:开工第一件事就测"某上下文规模下单步端到端多少秒",反推每题步数上限,再回头校准 §11 的时间预算。
- **缓存友好排布**(§6.4)把重复 prefill 降到最低——这是延迟的头号杠杆。
- **设计目标是"少而精的步骤"**:厚工具(§5)本就减少往返,确定性预处理(§5.3)把廉价信息一次喂饱 Planner,都是在省步数。

---

## 8. 题型路由(Planner 分类 → Executor 走对策略)

不同 rev 题型的解法路径完全不同,Planner 分类后,Executor 按类型选工具:

| 题型 | 识别特征 | 主策略 |
|---|---|---|
| **flag 校验函数** | 有明显"读输入→变换→比较"逻辑 | `ida.decompile` 读懂逻辑 → `solve.locate_targets` 定位成功/失败地址 → `solve.z3` 建约束 或 `solve.angr` 自动求解 → `solve.verify` 回验 |
| **加密/编码** | 导入表有 crypto 符号 / 识别出标准常量(如 AES S-box) | 识别算法 → 手工/z3 逆运算;`solve.unicorn` 跑解密函数 |
| **VM 混淆** | 大 dispatch 循环 + handler 表 | 识别 opcode → handler 映射 → 写模拟器 / `solve.unicorn` 逐 handler |
| **加壳** | DIE 检测到壳 / 高熵 / 少量导入 | `analyze.unpack_upx`;非 UPX 壳走 `solve.unicorn` **静态模拟**自解压段再 dump(不真跑程序) |
| **反调试** | 检测 ptrace/时间差 | 静态绕过(patch)+ 静态分析;或 `solve.unicorn` 隔离执行绕开反调试 |
| **运行时解密字符串** | `analyze.floss` 出线索 / 静态看不到明文 | FLOSS 提取;或 `solve.unicorn` 模拟解密函数还原数据 |

> **⚠️ 范围与已知限制(动态执行不在本期范围)**:本框架**不真正运行目标程序**——宿主是 macOS ARM64,无法原生跑 Linux x86-64 ELF,且本期已决定**不引入 qemu / Linux VM**。因此"必须整程序动态执行才能解"的题(重度反调试、需真跑才自解压的壳、复杂运行时解密)会退化到 **静态 + unicorn 片段模拟 + angr** 组合;这套覆盖不到的记为**已知盲区**,遇到直接判超范围、换下一题(§11),不在其上空耗预算。后续要补,再作为扩展项引入 qemu-user + IDA 远程调试。

---

## 9. 离线准备清单(⭐ 线下比赛前必须完成)

> 运行期无网,**任何遗漏的依赖 = 赛场上死路**。开赛前逐项打勾。

### 9.1 模型与推理
- [ ] Qwen3.6-35B-A3B 6-bit 权重已下载到本地
- [ ] 推理运行时(MLX 或 llama.cpp)已安装,`http://127.0.0.1:7777` 能起(OpenAI 兼容接口)
- [ ] 验证 8-bit KV cache + 64k 上下文能加载且不 swap
- [ ] 验证模型的 **tool-calling / structured output** 在离线端点上工作正常

### 9.2 IDA(全架构 license 已具备)
- [ ] IDA 已安装,**license 文件在本地**,全架构反编译器可用(x86-64 / ARM64 / MIPS / PPC / RISC-V …)
- [ ] **确认 IDA 大版本 ≥ 9.0**(idalib 后端的前提)。若为 8.x,`headless-ida` 改走 `idat64` batch 模式,需单独验证该路径
- [ ] `idalib` 已通过 `py-activate-idalib.py` 激活(`IDADIR=/Applications/IDA Professional X.app/Contents/MacOS`)
- [ ] **断网 dry-run(一票否决项)**:完全离线下用这张 license 让 idalib 成功加载并反编译一个样本。license 覆盖架构 ≠ idalib 离线一定能起,这步必须赛前跑通
- [ ] `headless-ida` 已安装,验证能 headless 反编译一个样本
- [ ] `mrexodia/ida-pro-mcp`(**开发调试 + 赛场人工干预**用,见 §11)已装

### 9.3 求解与分析工具(全部离线可用)
- [ ] `angr` + `claripy` + `z3-solver`(注意 angr 依赖较多,提前装全)
- [ ] `unicorn`、`capstone`、`keystone`
- [ ] `FLOSS`(FLARE 混淆字符串提取)
- [ ] `Detect-It-Easy`(`diec` CLI)
- [ ] `UPX`、`binwalk`
- [ ] `pwntools`(即使不打 pwn,其 ELF 解析/打包工具有用)、`radare2`/`rizin`(备用反汇编)

### 9.4 Python 环境
- [ ] **冻结的 venv**:所有依赖(`langchain`、`langgraph`、`angr`、…)已装入一个可复制的虚拟环境
- [ ] **本地 wheelhouse**:`pip download` 把所有依赖 wheel 缓存到本地目录,以便赛场重建/修复(`pip install --no-index --find-links=./wheelhouse`)
- [ ] 记录完整 `requirements.txt` + Python 版本

### 9.5 数据/签名 + 评估集
- [ ] IDA FLIRT 签名库(识别库函数,省 Agent 精力)
- [ ] 常见加密算法常量库(供本地识别 AES/DES/SHA 等)
- [ ] **按 §8 题型分类的评估集**:每类题型至少 1–2 道往届真题,逐条验证每个路由分支真能走通(不是随便几道样本)
- [ ] **评估指标就绪**:解出率 / 平均步数 / token 消耗 / 墙钟时间 / 失败卡在哪一步——一个"可靠性就是全部问题"的 Agent,必须有这个测量回路(见 §14 第 0 步)

### 9.6 框架自身
- [ ] 全部代码就位,`main` 能一键对一个二进制启动流程
- [ ] 日志目录、SQLite 记忆库初始化脚本就绪

---

## 10. 日志系统

你给的人类可读格式很好,建议**双轨**:一份机器可解析(用于回放/复盘/优化 prompt),一份人类可读(用于赛场实时观察)。

### 10.1 机器可读(JSONL,每行一事件)

```json
{"ts":"2026-07-18T10:30:00Z","run_id":"chall_A","agent":"executor","step":3,"type":"tool_call","tool":"solve.angr","args":{"binary":"./chall","find":"0x401234"},"tokens":{"prompt":18234,"completion":512},"ctx_used":21050}
{"ts":"...","run_id":"chall_A","agent":"executor","step":3,"type":"tool_result","tool":"solve.angr","status":"ok","result_summary":"found input: flag{...}","duration_s":12.4,"mem_peak_mb":2100}
```

**建议记录的字段/事件类型**:`planner_thinking`、`plan_md`(整份 Plan 快照)、`executor_thought`、`tool_call`、`tool_result`、`context_compression`(何时压缩、压掉多少)、`replan`(重规划触发+原因)、`error`、`flag_found`、`run_summary`。附带 **token 用量**和**内存峰值** —— 复盘时能定位是上下文管理还是内存出的问题。

### 10.2 人类可读(你给的格式,略作规范)

```
[USER]      对 ./chall 启动逆向,目标:提取 flag
[PLANNER]   (thinking) 先看 file_info + DIE...判断为 x86-64 无壳,有可疑 check 函数...
[PLAN.md]   Step1: 反编译 main;Step2: 定位校验;Step3: angr 求解
─────────────────────────────────────────────
[EXECUTOR][step 1][THOUGHT]  Plan 要求先看 main,调用 ida.decompile
[EXECUTOR][step 1][ACTION]   ida.decompile(name="main")
[EXECUTOR][step 1][RESULT]   main 调用 sub_401080 做校验,输入 argv[1]  (完整伪代码见记忆库 fn#12)
[EXECUTOR][step 2][THOUGHT]  校验在 sub_401080,反编译它
...
[EXECUTOR][step 4][ACTION]   solve.angr(binary="./chall", find=0x401234, avoid=[0x401250])
[EXECUTOR][step 4][RESULT]   ✅ flag{r3v3rs3_m4st3r}
[FLAG]      flag{r3v3rs3_m4st3r}  (flag_check: PASS)
```

> 注意人类可读日志里,长输出用"见记忆库 fn#12"引用,**不把整段伪代码打进日志** —— 和上下文策略一致,保持可读。

---

## 11. 错误处理与鲁棒性

CTF 赛场时间紧、样本敌意,鲁棒性直接决定能解几题:

- **全局超时预算**:每题设**时间上限**(如 20 分钟),到点无论进度记录现状、标失败、**换下一题**。别让一道题吃光整场时间。
- **工具级超时**:IDA 分析、angr explore、terminal 命令各自超时;angr 尤其要设**状态数上限**防路径爆炸把内存打爆。
- **进程隔离**:IDA/angr 在受管子进程跑;崩溃 → 捕获 → Agent 拿到"工具失败"观察,继续决策,而不是整个框架挂。
- **工具调用纠错**:本地模型可能产出畸形 tool call / 错参数。工具侧做**参数校验 + 明确报错信息 + 自动重试**(把错误回喂让模型改),别指望它一次对。
- **无进展检测**:`stuck_counter` 触发重规划(§3.4);重规划次数上限触发换题。
- **优雅降级**:angr 超时 → 回退让模型尝试 z3 手工建模;反编译失败 → 回退看反汇编。
- **跨题 triage(全局调度)**:开场先对所有题跑一遍确定性预分析(§5.3),按"快速能拿分"排序,先打软柿子,别从第一题死磕到底。单题超预算就换,拿分优先。
- **人工干预钩子(copilot 模式)**:线下赛你人就在旁边,一个 3B 激活的模型全自动大概率打不过"人用同样工具"。至少留一个干预点——每步可暂停、注入人类提示、或经 `ida-pro-mcp`(§9.2)直接接管纠偏。把目标从"能否全自动解出"放宽成"人机协作多快解出"。
- **编排器自身可恢复**:工具子进程隔离之外,主进程 / 模型 server OOM 挂掉时,用 LangGraph checkpointer 让整局 run 能 resume,而不只是开发期调试用。

---

## 12. 模型适配注意事项(针对 Qwen 35B-A3B 6bit)

- **不用裸依赖 native function-calling**:本地模型的原生工具调用可能不稳。考虑用**更显式的 ReAct 文本协议 + 严格输出解析 + 重试**,或 LangChain 的 structured output 配校验。实测你的端点后定。
- **给 few-shot 工具调用范例**:在系统 prompt 里放 1–2 个"如何正确调用工具"的示例,显著提升弱模型的调用可靠性。
- **厚工具降低编排负担**(呼应原则 3):工具越少越高层,模型跑飞概率越低。
- **6-bit 质量要守住**:别为省内存降到更低量化换窗口 —— 3B 激活的推理力经不起再掉。内存诉求交给 §6/§7 解决。

---

## 13. 建议项目结构

```
antiReverse/
├── main.py                  # 入口:对一个二进制启动流程
├── requirements.txt
├── wheelhouse/              # 离线 pip wheel 缓存
├── config.py                # 端点/路径/内存阈值/超时预算
├── graph/
│   ├── build.py             # LangGraph StateGraph 组装
│   ├── state.py             # 全局状态定义
│   ├── planner.py           # Planner 节点
│   └── executor.py          # Executor (ReAct) 节点 + 上下文管理
├── tools/
│   ├── ida_tools.py         # 基于 headless-ida 的静态厚工具
│   ├── solve_tools.py       # angr / z3 / unicorn 厚工具
│   ├── analyze_tools.py     # DIE / floss / upx / binwalk 预处理
│   └── terminal_tool.py     # 带超时/隔离的命令执行
├── memory/
│   ├── store.py             # SQLite 外部记忆层
│   └── context.py           # Working Memory + 历史压缩逻辑
├── logging/
│   └── logger.py            # JSONL + 人类可读双轨
├── isolation/
│   └── subprocess_runner.py # 受管子进程 + 超时 + 崩溃隔离
└── tests/
    └── samples/             # 往届 rev 样本,赛前跑通
```

---

## 14. 建议实施顺序(先跑通闭环,再加强)

0. **先搭评估回路 + 钉死两个实测数**:准备好 §9.5 的分类评估集与指标脚本;**开工第一天就实测两件事**——(a) idalib 离线 dry-run(§9.2),(b) 单步端到端延迟以反推每题步数(§7.4)。这两个数决定后面所有设计,别拖到最后。
1. **MVP 单 Agent**:先只做 Executor + `ida.decompile` + `terminal` + `solve.angr` + `solve.locate_targets` + `solve.verify`,手写一个固定 Plan,对一道简单 flag 校验题**跑通端到端**(反编译→定位→angr→回验出 flag)。验证工具链和内存都 OK。
2. **加外部记忆 + 上下文压缩**(§6):让它能处理稍复杂、多函数的题而不爆上下文;此时就按缓存友好排布(§6.4)落地。
3. **加 Planner + LangGraph 编排**:双 Agent + Plan.md。
4. **加反馈回路 + 题型路由**(§3.4/§8):处理需要重规划的题。
5. **补全求解与分析工具**(§5.2/5.3):z3 模板、unicorn、FLOSS、DIE、脱壳。
6. **鲁棒性 + 日志 + 超时预算 + 人工干预钩子**(§10/§11):赛场化。
7. **离线固化 + 评估集回归**(§9):全流程离线跑通分类评估集,用 §9.5 指标查漏补缺。

---

## 附:与原计划的主要差异

| 你的原计划 | 本补充 |
|---|---|
| Executor 只有 `ida headless` + `terminal` | **新增求解工具集 angr/z3/unicorn(核心解题引擎)** + 辅助分析工具,terminal 降为杂项兜底 |
| "需要很好的上下文管理策略"(未展开) | **四层策略**:Working Memory / 历史压缩 / SQLite 外部记忆 / 预算分配(§6) |
| Planner→Executor 单向 | **加反馈回路**:卡住可重规划(§3.4) |
| 未提终止/成功判定 | **flag 格式验证** + 无进展检测 + 时间预算(§3.3/§11) |
| 三选一 IDA 库 | **决策:headless-ida 引擎 + 自研厚工具;GUI-MCP 仅开发用**(§4) |
| 用 LangChain | **建议用 LangGraph**(有状态多 Agent 的正解)(§3.1) |
| "工具提前准备好"(一句话) | **完整离线准备清单**(§9) |
| 日志人类可读格式 | **双轨:JSONL 机器可读 + 人类可读**(§10) |
| 未涉及内存 | **48GB 硬账 + 8-bit KV + 串行工具 + 第二机后路**(§7) |

---

## 附 2:本轮修订记录(基于「全架构 IDA license + 本期不引入动态执行 VM + Executor 不开 thinking」几项决定)

| 改动 | 位置 | 说明 |
|---|---|---|
| **去掉 Ghidra** | §5.2 | 全架构 IDA 反编译顶上,Ghidra 不再需要,连"架构兜底保险"也不留 |
| **angr 降为纯求解引擎** | §2 原则 2 / §5.2 | 不再兼"架构兜底";明确它不是银弹,别当框架支柱 |
| **动态执行明确出范围** | §8 | 不引入 qemu/VM,dump-by-running 类题记为已知盲区,遇到即换题;后续可作扩展项 |
| **Executor 明确不开 thinking** | §3.3 | ReAct 的 Thought 已承担推理,叠 thinking 翻倍延迟且弱模型易跑飞;Planner 仍可 thinking 但需实测校验(§3.2) |
| **成功判据强化** | §3.3 / §5.2 `solve.verify` | 候选 flag 用 unicorn 回验二进制自身校验,而非只看格式 |
| **新增 `solve.locate_targets`** | §5.2 | 确定性推导 angr 的 find/avoid,堵上"让弱模型猜地址"的漏洞 |
| **缓存友好的上下文排布** | §6.4 | 稳定前缀在前、易变在后,最大化跨步 KV 复用,省本地 prefill 延迟 |
| **补延迟账** | §7.4 | 内存之外,量化单步 prefill 延迟 → 每题步数上限 |
| **评估回路前置** | §9.5 / §14 第 0 步 | 分类评估集 + 指标,开工先测 idalib dry-run 与单步延迟 |
| **人工干预钩子** | §11 | copilot 模式:可暂停 / 注入提示 / 经 ida-pro-mcp 接管 |
| **跨题 triage + 编排器可恢复** | §11 | 先打软柿子;主进程崩溃用 checkpointer resume |
| **型号待钉死** | §1.2 | 确认是 30B 还是 35B,内存账依赖它 |