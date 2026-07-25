"""report_schema 纯离线单测:字段校验 / 杀幻觉工具 / 渲染含字段值 / tool_calls 解析。"""
from antirev.tools.report_schema import (
    REPORT_PROGRESS, EMIT_PLAN,
    validate_report, validate_plan,
    render_report, render_plan, parse_tool_args,
)


def test_validate_report():
    # 缺 next_steps → 返回含 "next_steps";key_data/tried 允许空
    d = {"confirmed_algo": "逐字节 xor 0x37 后与密文比较", "key_data": [], "tried": [],
         "blocker": "密文真实地址未定", "next_steps": []}
    miss = validate_report(d)
    assert "next_steps" in miss
    # 字段齐全 → []
    d["next_steps"] = ["按 data_refs 读密文再逆 xor"]
    assert validate_report(d) == []


def test_validate_plan_kills_hallucinated_tool():
    tool_names = {"ida_decompile", "run_python"}
    bad = {"problem_type": "xor",
           "steps": [{"goal": "动态调试看解密", "tool": "x64dbg", "success_criteria": "看到明文"}]}
    errs = validate_plan(bad, tool_names)
    assert errs and any("x64dbg" in e for e in errs)
    # 工具合法 → []
    good = {"problem_type": "xor",
            "steps": [{"goal": "反编译 main", "tool": "ida_decompile", "success_criteria": "拿到伪代码"}]}
    assert validate_plan(good, tool_names) == []
    # steps 为空 → 报错
    assert validate_plan({"problem_type": "xor", "steps": []}, tool_names)


def test_render_contains_fields():
    rep = render_report({
        "confirmed_algo": "flag 逐字节 xor 0x5a 后与密文比较",
        "key_data": [{"addr": "0x4020", "value": "3a1b2c", "meaning": "密文"}],
        "tried": [{"approach": "angr 符号执行", "why_failed": "路径爆炸超时"}],
        "blocker": "angr 跑不出,得改写 run_python 逐字节逆",
        "next_steps": ["读密文字节逐字节逆 xor"],
    })
    assert "xor 0x5a" in rep and "0x4020" in rep and "angr" in rep and "run_python" in rep

    plan = render_plan({
        "problem_type": "异或加密",
        "arch": "x86-64 ELF",
        "key_findings": ["密钥 0x37"],
        "key_code": [{"func": "check", "addr": "0x401200", "note": "逐字节 xor"}],
        "steps": [{"goal": "读密文", "tool": "ida_read_bytes", "success_criteria": "拿到 32 字节"}],
        "flag_format": "NSSCTF{...}",
    })
    assert ("异或加密" in plan and "0x401200" in plan
            and "ida_read_bytes" in plan and "NSSCTF{...}" in plan)


def test_parse_tool_args():
    msg = {"tool_calls": [{"function": {"name": "emit_plan",
                                        "arguments": "{\"problem_type\":\"xor\",\"steps\":[]}"}}]}
    assert parse_tool_args(msg, "emit_plan").get("problem_type") == "xor"
    # 找不到工具名 / 空 message / 坏 json → {}
    assert parse_tool_args(msg, "no_such") == {}
    assert parse_tool_args({}, "emit_plan") == {}
    bad = {"tool_calls": [{"function": {"name": "emit_plan", "arguments": "{not json"}}]}
    assert parse_tool_args(bad, "emit_plan") == {}


def test_schemas_are_openai_tool_shape():
    for schema, name, required in ((REPORT_PROGRESS, "report_progress",
                                    {"confirmed_algo", "key_data", "tried", "blocker", "next_steps"}),
                                   (EMIT_PLAN, "emit_plan", {"problem_type", "steps"})):
        assert schema["type"] == "function"
        fn = schema["function"]
        assert fn["name"] == name
        assert fn["parameters"]["type"] == "object"
        assert required <= set(fn["parameters"]["required"])
