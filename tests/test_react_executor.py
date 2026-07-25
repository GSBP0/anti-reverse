"""自研 ReAct Executor:原生 tool_calls decode 单测(离线) + 消息回放格式 + 模型驱动端到端(需端点)。"""
import urllib.request
from pathlib import Path

import pytest

from antirev import config
from antirev.react_executor import ReactExecutor, decode_native

ROOT = Path(__file__).resolve().parent.parent
PLAN = str(ROOT / "tests/fixtures/plan_flagcheck.md")


def _endpoint_up():
    try:
        urllib.request.urlopen(config.MODEL_BASE_URL.rstrip("/") + "/models", timeout=2)
        return True
    except Exception:
        return False


def _msg(content=None, name=None, arguments=None):
    """构造一条模型响应 message dict(模拟 mlx_lm.server 原生 tool_calls 输出)。"""
    m = {"content": content}
    if name is not None:
        m["tool_calls"] = [{"id": "c1", "type": "function",
                            "function": {"name": name, "arguments": arguments}}]
    return m


# —— decode_native 单元测试 ——

def test_decode_action():
    kind, tool, args, thought, flag = decode_native(_msg("先定位", "solve_locate", "{}"))
    assert kind == "action" and tool == "solve_locate" and args == {} and thought == "先定位"


def test_decode_action_with_args():
    kind, tool, args, thought, flag = decode_native(_msg("符号执行", "solve_angr", '{"stdin_len": 17}'))
    assert kind == "action" and tool == "solve_angr" and args["stdin_len"] == 17


def test_decode_submit_flag_is_final():
    kind, tool, args, thought, flag = decode_native(_msg("提交", "submit_flag", '{"flag": "flag{abc}"}'))
    assert kind == "final" and flag == "flag{abc}"


def test_decode_no_toolcall_is_none():
    kind, tool, args, thought, flag = decode_native(_msg("我不知道该怎么做"))
    assert kind == "none" and thought == "我不知道该怎么做" and tool is None


def test_decode_malformed_args_degrades():
    """arguments 非法 JSON → args 退化为 {},不崩(原生下罕见,但要稳)。"""
    kind, tool, args, thought, flag = decode_native(_msg("试试", "ida_decompile", "{not json"))
    assert kind == "action" and tool == "ida_decompile" and args == {}


def test_decode_strips_thought_prefix():
    """模型自带的 'THOUGHT:' 前缀被剥掉,避免窗口回放叠字。"""
    _, _, _, thought, _ = decode_native(_msg("THOUGHT: 先反编译", "ida_decompile", '{"name_or_addr":"main"}'))
    assert thought == "先反编译"
    _, _, _, th2, _ = decode_native(_msg("THOUGHT：定位", "solve_locate", "{}"))  # 全角冒号
    assert th2 == "定位"


def test_decode_final_labels_submit_flag():
    """submit_flag 的 tool 记为 'submit_flag'(便于日志),仍判 final。"""
    kind, tool, args, thought, flag = decode_native(_msg("提交", "submit_flag", '{"flag":"flag{x}"}'))
    assert kind == "final" and tool == "submit_flag" and flag == "flag{x}"


# —— 上下文窗口原生回放格式(P3)——

def test_build_messages_native_format():
    from antirev.memory.store import MemoryStore
    from antirev.memory.context import ContextManager
    store = MemoryStore(":memory:")
    try:
        ctx = ContextManager(store, "t", window=4)
        ctx.set_goal("g")
        ctx.push_exchange("先反编译", "ida_decompile", {"name_or_addr": "main"}, "OBSERVATION: {}")
        ctx.push_exchange("没调工具", None, None, "请调用工具")
        msgs = ctx.build_messages("SYS", "task")
        # assistant.tool_calls 存在,且与随后的 role:tool 用同一 tool_call_id 配对
        asst = [m for m in msgs if m["role"] == "assistant" and m.get("tool_calls")]
        assert asst and asst[0]["tool_calls"][0]["function"]["name"] == "ida_decompile"
        tc_id = asst[0]["tool_calls"][0]["id"]
        tool_msgs = [m for m in msgs if m["role"] == "tool"]
        assert tool_msgs and tool_msgs[0]["tool_call_id"] == tc_id
        # tool=None 的往返回放为 assistant(content) + user
        assert any(m["role"] == "user" and m["content"] == "请调用工具" for m in msgs)
    finally:
        store.close()


# —— 反假阳性 grounding(原生 submit_flag 路径)——

def test_rejects_hallucinated_flag_accepts_grounded(sample):
    """编造的 flag(未在工具输出出现)被拒;run_python 真实算出的被接受。"""
    class FakeClient:
        def __init__(self):
            self.calls = 0
            self.last_prompt_tokens = None

        def complete_tools(self, messages, **kw):
            self.calls += 1
            if self.calls == 1:   # 编造 flag → 应被拒(没在任何工具输出出现过)
                return _msg("提交", "submit_flag", '{"flag": "flag{fabricated_never_seen_anywhere}"}')
            if self.calls == 2:   # 真实算出并 print
                return _msg("算一下", "run_python", '{"code": "print(\'flag{real_computed_123}\')"}')
            return _msg("提交真解", "submit_flag", '{"flag": "flag{real_computed_123}"}')

    ex = ReactExecutor(sample, client=FakeClient(), max_steps=6)
    r = ex.run("solve it")
    assert r["flag"] == "flag{real_computed_123}"
    assert r["steps"] >= 3       # 第1次编造被拒,继续到真实算出


# —— recall 分页(应对反编译/反汇编大返回)——

def test_recall_dispatch_paginates(sample):
    """recall 走分页:300 行伪代码按 num=100 分 3 页,首页 has_next=True 指示翻页(旧 {'full':...} 实现无这些键)。"""
    import json as _json
    from antirev.memory.store import MemoryStore
    ex = ReactExecutor(sample, client=object(), max_steps=1)
    store = MemoryStore(":memory:")
    aid = store.put_artifact("exec", "ida_decompile", {"name_or_addr": "main"},
                             "sum", _json.dumps({"pseudocode": "\n".join(f"L{i}" for i in range(300))}))
    out = ex._dispatch("recall", {"artifact_id": aid, "page": 1, "num": 100}, store)
    assert out["total_pages"] == 3 and out["has_next"] is True
    assert out["text"].startswith("L0")
    assert out["tool"] == "ida_decompile"


def test_dispatch_forwards_fingerprint_and_outline(sample):
    """_dispatch 必须转发 worker 的 fingerprint_feat + outline(修指纹断链)。
    旧实现重打包时丢弃 → 台账 fp 恒空;此测试 RED today、P0 修后 GREEN。用 stub 避免真机。"""
    from antirev.memory.store import MemoryStore
    from antirev.memory.context import ContextManager
    FEAT = {"loops": 1, "ops": [["xor", 0x37]], "cmps": 1, "cmp_imms": [],
            "calls": [], "strs": ["Correct"], "input": False, "size": 50}
    OUTLINE = {"addr": 0x1000, "n_blocks": 8, "n_insn": 60, "segments": [
        {"id": 0, "start": "0x1000", "end": "0x1020", "n_insn": 30, "kind": "linear",
         "feat": FEAT, "score": 1, "core": False},
        {"id": 1, "start": "0x1020", "end": "0x1040", "n_insn": 30, "kind": "loop",
         "feat": FEAT, "score": 9, "core": True}]}

    class StubIda:
        def decompile(self, noa):
            return {"pseudocode": "void f()", "data_refs": [], "callees": [],
                    "fingerprint_feat": FEAT, "outline": OUTLINE}

    ex = ReactExecutor(sample, client=object(), max_steps=1)
    ex._get_ida = lambda: StubIda()
    store = MemoryStore(":memory:")
    obs = ex._dispatch("ida_decompile", {"name_or_addr": "f"}, store)
    assert "fingerprint_feat" in obs and "outline" in obs   # 两键都被转发(修断链)
    ctx = ContextManager(store, "r1")
    ctx.record(1, "ida_decompile", {"name_or_addr": "f"}, obs)
    assert ctx.func_map["f"]["fp"]                          # rail 通到台账:指纹渲染非空


@pytest.mark.skipif(not _endpoint_up(), reason="model endpoint offline")
def test_model_driven_end_to_end(sample, expected_flag):
    ex = ReactExecutor(sample)
    result = ex.run(open(PLAN).read())
    assert result["flag"] and expected_flag in result["flag"], result
