antiReverse

## 背景
一个用于线下CTF比赛的逆向工程agent框架，只打逆向题目,且线下CTF比赛不准联网，只能够提前把所有工具在本地给agent准备好
### 本机配置
内存:48g
CPU:M4
型号: MacOS Pro Max
### 模型参数
本地模型:Qwen-35b-a3b-6bit 
上下文:64k
api端点:http://127.0.0.1:7777

## 技术栈构思:
主要使用LangChain来进行大模型的编排等工作，初步设定使用双Agent来作为这个agent框架:
1. Planner:初步收集题目所有信息，并对接下来的步骤进行思考和规划，最终产出一个Plan.md供给接下来的Agent思考，使用thinking
2. Executor: ReAct Agent,每次将系统prompt+Plan.md作为初始prompt开始,并提供ida headless,terminal两个工具进行各类操作,同时这个Agent也需要一个非常好的上下文管理策略，让上下文尽量概括当前全部的进度并且能够让agent顺着上一步继续往下做,直到达到plan.md要求的目的为止


## 工具层面:
关于ida有以下几个选择，你可以选择一个作为逆向工具库直接加入到agent框架中，也可以吸收精华和结合背景情况开发一个最佳的工具选择:
headless:https://github.com/blacktop/ida-mcp-rs
headless:https://github.com/DennyDai/headless-ida
gui-mcp:https://github.com/mrexodia/ida-pro-mcp

terminal:执行本地命令的工具

## 日志所需
你需要记录Agent所有的行为和思考过程到本地的日志中,大致形式需要如下,...代表省略
Example:
[user]
调用termianl工具执行whoami命令
[LLM thinking]
用户让我使用terminal工具执行whoami命令.....
[LLM]
好的我马上调用.....
[LLM_toolCalling]
termianl:
args:whoaml
response: command not found: whoaml
## Web 作战台
单题可视化控制台(`antirev/web/`):题目参数输入、开始/暂停/继续/停止、Human-in-the-loop 提示、
实时做题进度。启动:
```bash
conda run -n antirev python -m antirev.web.server   # → http://127.0.0.1:8765
```
Web 只是日志消费者 + 控制文件写入者(tail `logs/<run_id>.jsonl`、写 `.ctl`/`.hint`),不参与解题——
Web 崩了 agent 照跑,agent 崩了 Web 照活,历史 run 可用同一套渲染回放。详见 `antirev/web/README.md`。

批量评测仍用 `scripts/eval.py`,不在本界面。
