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
    big = {"pseudocode": "X" * 5000, "callees": [{"addr": "0x1", "name": "check"}], "data_refs": []}
    obs_txt = ctx.record(1, "ida_decompile", {"name_or_addr": "main"}, big)
    assert "artifact#" in obs_txt          # 上下文里含 artifact 引用
    assert len(obs_txt) < 5000             # 已压缩,未塞全 5000 字符原文
    assert s.find_cached("r1", "ida_decompile", {"name_or_addr": "main"})  # 已入库(缓存)


def test_context_window_bounded():
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1", window=3)
    for i in range(1, 11):
        ctx.record(i, "ida_read_bytes", {"a": i}, {"hex": "aa", "size": 1, "addr": hex(i)})
        ctx.push_exchange(f"THOUGHT step{i}", f"OBSERVATION {i}")
    msgs = ctx.build_messages("SYS", "解题任务")
    # system + (task+WM) + 最近 3 步的 (assistant,user) = 2 + 6 = 8
    assert len(msgs) == 2 + 3 * 2
    wm = ctx.working_memory_block()
    assert "步1:" in wm and "步7:" in wm    # 早前步骤压进 WM
    assert "步10:" not in wm                # 最近的在窗口里,不在 WM 压缩区


def test_context_recall_via_store():
    s = MemoryStore(":memory:")
    ctx = ContextManager(s, "r1", window=3)
    ctx.record(1, "ida_decompile", {"name_or_addr": "main"}, {"pseudocode": "SECRET" * 500})
    hit = s.find_cached("r1", "ida_decompile", {"name_or_addr": "main"})
    art = s.get_artifact(hit["id"])
    assert "SECRET" in art["full_text"]
