"""算法指纹:把函数的算法骨架(抽取自汇编)渲染成一行高密度摘要,替代 func_map 的裸签名。

feat 契约(worker 侧 _fingerprint 产出、render_fingerprint 消费):
  {loops:int, ops:[(mnem,imm|None)], cmps:int, cmp_imms:[int], calls:[str], strs:[str], input:bool, size:int}
一行指纹保留写 solve 所需的常量与结构(如 xor 0x37 / 循环次数 / 对错串),全文仍可 recall 分页。
"""
from antirev.memory.context import render_fingerprint


def test_render_includes_loop_and_immediate_op():
    # flagcheck 真实形态:循环逐字节 xor 0x37 再比较
    feat = {"loops": 1, "ops": [("xor", 0x37)], "cmps": 1, "cmp_imms": [],
            "calls": [], "strs": ["Correct", "Wrong"], "input": False, "size": 100}
    fp = render_fingerprint(feat)
    assert "loop×1" in fp
    assert "xor 0x37" in fp                    # 关键:密钥常量保留在指纹里


def test_render_shows_cmp_immediates():
    feat = {"loops": 0, "ops": [], "cmps": 2, "cmp_imms": [0x41, 0x42],
            "calls": [], "strs": [], "input": False, "size": 50}
    fp = render_fingerprint(feat)
    assert "0x41" in fp and "0x42" in fp        # 逐字节比较的目标值(即密文)保留


def test_render_lists_calls_and_refs():
    feat = {"loops": 0, "ops": [], "cmps": 1, "cmp_imms": [], "calls": ["memcmp"],
            "strs": ["flag"], "input": True, "size": 80}
    fp = render_fingerprint(feat)
    assert "memcmp" in fp
    assert "flag" in fp


def test_render_op_without_immediate_omits_none():
    feat = {"loops": 0, "ops": [("shl", None)], "cmps": 0, "cmp_imms": [],
            "calls": [], "strs": [], "input": False, "size": 30}
    fp = render_fingerprint(feat)
    assert "shl" in fp
    assert "None" not in fp                     # 无立即数不渲染 None


def test_render_empty_feat_is_safe():
    feat = {"loops": 0, "ops": [], "cmps": 0, "cmp_imms": [], "calls": [],
            "strs": [], "input": False, "size": 10}
    assert isinstance(render_fingerprint(feat), str)   # 无特征也不报错


def test_render_is_single_line_even_with_newline_in_strs():
    # 真机发现:引用串含 \n(Correct\n/Wrong\n)会让指纹跨行,破坏"一行高密度"
    feat = {"loops": 0, "ops": [], "cmps": 0, "cmp_imms": [],
            "calls": [], "strs": ["Correct\n", "Wrong\n"], "input": False, "size": 10}
    fp = render_fingerprint(feat)
    assert "\n" not in fp                       # 指纹必须单行
    assert "Correct" in fp


def test_render_fingerprint_caps_long_ops():
    # 真机发现(funnyre main):花指令有几百个不同 xor 立即数,指纹不能全渲染成几千字符 —— 必须有上限
    feat = {"loops": 1, "ops": [["xor", i] for i in range(200)], "cmps": 0, "cmp_imms": [],
            "calls": [], "strs": [], "input": False, "size": 100}
    fp = render_fingerprint(feat)
    assert len(fp) < 200                        # 不因几百 ops 爆成几千字符(旧版 ~2000+)
    assert "+" in fp                            # 标注省略了多少(…+N)


def test_render_fingerprint_caps_long_cmp_imms():
    feat = {"loops": 0, "ops": [], "cmps": 300, "cmp_imms": list(range(300)),
            "calls": [], "strs": [], "input": False, "size": 100}
    fp = render_fingerprint(feat)
    assert len(fp) < 200
