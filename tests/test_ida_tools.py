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
    # 0x400105 = "Correct\n";应有来自 correct 分支 lea 的 xref
    with IdaSession(sample) as ida:
        refs = ida.xrefs_to(0x400105)
        assert any(0x400078 <= x["frm"] < 0x4000f4 for x in refs), refs
