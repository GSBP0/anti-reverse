"""基于 LangGraph create_react_agent 的 Executor(依赖**原生 OpenAI tool_calls**)。

⚠️ 本机端点是 mlx_lm.server,不解析原生 tool_calls,故此路径在当前端点**不可用**;
   实际生产走 antirev.react_executor(自研文本协议)。本模块留作**支持原生 tool_calls
   的端点**(如带工具解析的 vLLM/TGI)备用,并作 LangChain 装配的冒烟参照。

- 工具 = 薄封装,复用 Task 4–8 的厚工具函数。
- 强成功判据:solve_verify 的 accepted=True 才算真 flag。
"""
from __future__ import annotations

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from antirev import config
from antirev.tools.ida_tools import IdaSession
from antirev.tools.solve_locate import locate_targets
from antirev.tools.solve_angr import solve_angr as _run_angr
from antirev.tools.solve_verify import verify_candidate
from antirev.tools.terminal import terminal as _run_terminal

SYSTEM_PROMPT = (
    "你是一个逆向工程 Executor。严格按给定 Plan,只用提供的工具解出 flag。\n"
    "关键原则:能确定性求解就别猜地址——先用 solve_locate 拿 find/avoid,再 solve_angr 求候选,"
    "最后 solve_verify 回验。只有 verify 返回 accepted=True 才是真 flag。\n"
    "拿到真 flag 后,用一行 'FLAG: <flag>' 明确输出并结束。"
)


def build_tools(binary: str):
    @tool
    def ida_decompile(name_or_addr: str) -> str:
        """反编译单个函数,返回伪代码(压缩切片)。参数:函数名或十六进制地址,如 '0x400078'。"""
        try:
            with IdaSession(binary) as ida:
                return ida.decompile(name_or_addr)["pseudocode"][:6000]
        except Exception as e:
            return f"ERROR: {e}"

    @tool
    def solve_locate() -> dict:
        """确定性推导 angr 的 find/avoid 地址(从成功/失败字符串反推)。无参数。返回 {find,avoid,evidence}。"""
        return locate_targets(binary)

    @tool
    def solve_angr(find: list[int], avoid: list[int], stdin_len: int = 32) -> dict:
        """符号执行求解:探索到 find、避开 avoid,返回满足输入。返回 {found,stdin}。"""
        return _run_angr(binary, find=find, avoid=avoid, stdin_len=stdin_len)

    @tool
    def solve_verify(candidate: str, find: int, avoid: int = None) -> dict:
        """把候选 flag 喂回二进制自身校验,确认走到 accept 分支。返回 {accepted,method}。"""
        return verify_candidate(binary, candidate, find=find, avoid=avoid)

    @tool
    def terminal(command: str) -> dict:
        """执行本地命令(超时+沙箱)。仅杂项兜底,solve.* 不要走这里。"""
        return _run_terminal(command)

    return [ida_decompile, solve_locate, solve_angr, solve_verify, terminal]


def build_executor(binary: str):
    llm = ChatOpenAI(base_url=config.MODEL_BASE_URL, api_key=config.MODEL_API_KEY,
                     model=config.MODEL_NAME, temperature=0)
    return create_react_agent(llm, build_tools(binary), prompt=SYSTEM_PROMPT)
