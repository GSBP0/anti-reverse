from antirev.tools.ida_tools import IdaSession


def test_lists_entry_function(sample):
    with IdaSession(sample) as ida:
        fns = ida.list_functions()
        assert any(f["name"] == "start" for f in fns), fns


def test_decompile_returns_pseudocode(sample):
    with IdaSession(sample) as ida:
        r = ida.decompile("0x400078")
        assert "pseudocode" in r
        assert "sys_read" in r["pseudocode"] or "read" in r["pseudocode"].lower()


def test_xrefs_to_message_string(sample):
    # "Correct" 串应有来自 correct 分支 lea 的 xref(地址动态取,不硬编码)
    with IdaSession(sample) as ida:
        correct = [s for s in ida.strings() if "Correct" in s["value"]]
        assert correct, "IDA 应检测到 Correct 串"
        refs = ida.xrefs_to(correct[0]["addr"])
        assert refs, "Correct 串应有 xref"
