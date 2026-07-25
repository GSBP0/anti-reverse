from antirev.memory.store import MemoryStore
from antirev.memory.context import ContextManager


def test_store_artifact_roundtrip():
    s = MemoryStore(":memory:")
    aid = s.put_artifact("r1", "ida_decompile", {"name_or_addr": "main"},
                         "反编译 main", "long pseudocode " * 100)
    got = s.get_artifact(aid)
    assert got["tool"] == "ida_decompile"
    assert "long pseudocode" in got["full_text"]


def test_store_cache_hit_by_args():
    s = MemoryStore(":memory:")
    s.put_artifact("r1", "ida_decompile", {"name_or_addr": "main"}, "sum", "FULL")
    hit = s.find_cached("r1", "ida_decompile", {"name_or_addr": "main"})
    assert hit and hit["full_text"] == "FULL"
    miss = s.find_cached("r1", "ida_decompile", {"name_or_addr": "other"})
    assert miss is None


def test_store_facts():
    s = MemoryStore(":memory:")
    s.put_fact("r1", "algo", "XOR 0x7A")
    facts = s.get_facts("r1")
    assert facts and facts[0]["value"] == "XOR 0x7A"


def test_context_compresses_big_obs_and_stores():
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1", window=3)
    # 花指令式重复 pass:内容感知折叠应把冗余大幅压短(治密度),而非硬截位置或塞全原文
    big = {"pseudocode": "start();\n" + "junk_pass();\n" * 400 + "return check();",
           "callees": [{"addr": "0x1", "name": "check"}], "data_refs": []}
    full_len = len(big["pseudocode"])
    obs_txt = ctx.record(1, "ida_decompile", {"name_or_addr": "main"}, big)
    assert "artifact#" in obs_txt              # 上下文里含 artifact 引用
    assert len(obs_txt) < full_len // 2        # 折叠后显著变短(重复冗余被压掉)
    assert s.find_cached("r1", "ida_decompile", {"name_or_addr": "main"})  # 已入库(缓存)
    assert "junk_pass();" in s.get_artifact(1)["full_text"]  # 全文无损留在 SQLite(可 recall 分页取回)


def test_context_window_bounded():
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1", window=3)
    for i in range(1, 11):
        args = {"name_or_addr": hex(i)}
        ctx.record(i, "ida_read_bytes", args, {"hex": "aa", "size": 1, "addr": hex(i)})
        ctx.push_exchange(f"THOUGHT step{i}", "ida_read_bytes", args, f"OBSERVATION {i}")
    msgs = ctx.build_messages("SYS", "解题任务")
    # system + (task+WM) + 最近 3 步,每步原生回放 (assistant.tool_calls, tool) = 2 + 3*2 = 8
    assert len(msgs) == 2 + 3 * 2
    # 窗口只含最近 3 步(step8-10);更早的原始往返滑出
    assert any("OBSERVATION 10" in (m.get("content") or "") for m in msgs)
    assert all((m.get("content") or "") != "OBSERVATION 1" for m in msgs)
    # 但早前步骤经结构化台账(ledger)持久留在 WM:读过的字节地址仍在
    wm = ctx.working_memory_block()
    assert "0x1" in wm and "0x7" in wm     # 早前读的字节在台账里持久(不随窗口滑出)
    assert "0xa" in wm


def test_context_recall_via_store():
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1", window=3)
    ctx.record(1, "ida_decompile", {"name_or_addr": "main"}, {"pseudocode": "SECRET" * 500})
    hit = s.find_cached("r1", "ida_decompile", {"name_or_addr": "main"})
    art = s.get_artifact(hit["id"])
    assert "SECRET" in art["full_text"]


def test_ledger_uses_algorithm_fingerprint():
    """反编译带 fingerprint_feat 时,台账(Working Memory)显示算法指纹而非只裸签名 —— executor 据此记住算法。"""
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1", window=3)
    obs = {"pseudocode": "void __noreturn start()", "callees": [], "data_refs": [],
           "fingerprint_feat": {"loops": 1, "ops": [["xor", 0x37]], "cmps": 1, "cmp_imms": [],
                                "calls": [], "strs": ["Correct"], "input": False, "size": 100}}
    ctx.record(1, "ida_decompile", {"name_or_addr": "start"}, obs)
    wm = ctx.working_memory_block()
    assert "xor 0x37" in wm          # 台账里有算法骨架(密钥常量),不只 void start()


def test_decompile_dump_folds_repeats():
    """planner 通读路径(decompile_dump)与 executor 视图统一:走折叠,不再是纯位置截断。"""
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1", window=3)
    big = "head\n" + "junk_pass();\n" * 500 + "tail"
    ctx.record(1, "ida_decompile", {"name_or_addr": "f"},
               {"pseudocode": big, "callees": [], "data_refs": []})
    dump = ctx.decompile_dump()
    assert "折叠" in dump           # 冗余走折叠(治密度),不再纯位置截断
    assert "artifact#" in dump      # 段头带 id,planner 可据此 recall 分页取全


def _big_outline():
    return {"addr": 0x401000, "n_blocks": 8, "n_insn": 60, "segments": [
        {"id": 0, "start": "0x401000", "end": "0x401020", "n_insn": 30, "kind": "linear",
         "feat": {"loops": 0, "ops": [], "cmps": 0, "cmp_imms": [], "calls": ["read"],
                  "strs": [], "input": True, "size": 30}, "score": 4, "core": False},
        {"id": 1, "start": "0x401020", "end": "0x401040", "n_insn": 30, "kind": "loop",
         "feat": {"loops": 1, "ops": [["xor", 0x37]], "cmps": 1, "cmp_imms": [], "calls": [],
                  "strs": ["Correct"], "input": False, "size": 30}, "score": 12, "core": True}]}


def test_outline_coverage_marks_seen():
    """record 带 outline 的 decompile → 台账显示段图、两段全 [未看];
    再 record 命中段 start 的 ida_disasm → 该段翻 [已看],未下钻计数减 1。"""
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1")
    ctx.record(1, "ida_decompile", {"name_or_addr": "0x401000"},
               {"pseudocode": "void f()", "callees": [], "data_refs": [], "outline": _big_outline()})
    wm = ctx.working_memory_block()
    assert "★" in wm and wm.count("[未看]") == 2      # 段图进台账,两段都未下钻
    ctx.record(2, "ida_disasm", {"name_or_addr": "0x401020"},
               {"disasm": "0x401020  xor al, 0x37", "callees": []})
    wm2 = ctx.working_memory_block()
    assert "[已看]" in wm2 and wm2.count("[未看]") == 1   # seg1(0x401020)翻已看,只剩 seg0


def test_decompile_dump_uses_outline_for_big_func():
    """planner 通读:大函数(有 outline + 长 code)用段图替代全文(治崩服务);小函数仍折叠全文。"""
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1")
    ctx.record(1, "ida_decompile", {"name_or_addr": "big"},
               {"pseudocode": "uniquebody\n" * 4000, "callees": [], "data_refs": [],
                "outline": _big_outline()})
    ctx.record(2, "ida_decompile", {"name_or_addr": "small"},
               {"pseudocode": "int small() { return 1; }", "callees": [], "data_refs": []})
    dump = ctx.decompile_dump()
    assert "★" in dump and "逐段下钻" in dump             # 大函数:段图 + 下钻提示
    assert "uniquebody\nuniquebody" not in dump           # 大函数全量 body 未内联(治崩服务)
    assert "int small()" in dump                          # 小函数:全文保留
