"""deobf 去花指令单测:纯离线,手工编码字节直接调 deflower_bytes(不碰二进制)。

字节均按 x86-64 手工编码;分支立即数在 capstone detail 下已是绝对目标地址。
"""
from antirev.tools.deobf import deflower_bytes


def test_xor_je_skips_junk():
    # xor eax,eax ; je 0x1006 ; <e8 cc 假call头,死路> ; mov eax,0xdeadbeef ; ret
    # 线性 sweep 会把 e8 cc b8 ef be 读成一条 call,吞掉真实 mov 的开头;
    # 递归遍历认出 xor 置 ZF=1 → je 恒真跳 0x1006,死路永不解码,真实 mov 自然对齐出来。
    blob = (bytes.fromhex("31c0")            # 0x1000 xor eax, eax
            + bytes.fromhex("7402")          # 0x1002 je 0x1006
            + bytes.fromhex("e8cc")          # 0x1004 假 call 头(junk,被跳过)
            + bytes.fromhex("b8efbeadde")    # 0x1006 mov eax, 0xdeadbeef(真实指令)
            + bytes.fromhex("c3"))           # 0x100b ret
    r = deflower_bytes(blob, 0x1000, "x86_64")

    assert r["ok"] is True
    assert any(p["kind"] == "xor_zf_je" for p in r["junk_patterns"]), r["junk_patterns"]
    # 真实指令被对齐出来
    assert "0xdeadbeef" in r["cleaned_disasm"], r["cleaned_disasm"]
    # 假 call 那 2 字节(0x1004..0x1006)是未到达的花指令区间
    assert ["0x1004", "0x1006"] in r["junk_ranges"], r["junk_ranges"]


def test_je_jne_uncond():
    # je 0x1008 ; jne 0x1008(同目标)→ 两分支都去 0x1008,等价无条件跳,跳过中间 4 字节 nop 死路。
    # (je=7406→0x1008, jne=7504→0x1008;两者同址 2 字节之差,rel8 须不同才同目标)
    blob = (bytes.fromhex("7406")            # 0x1000 je 0x1008
            + bytes.fromhex("7504")          # 0x1002 jne 0x1008
            + bytes.fromhex("90909090")      # 0x1004 junk(被跳过)
            + bytes.fromhex("c3"))           # 0x1008 ret
    r = deflower_bytes(blob, 0x1000, "x86_64")

    assert r["ok"] is True
    assert any(p["kind"] == "je_jne" for p in r["junk_patterns"]), r["junk_patterns"]
    assert ["0x1004", "0x1008"] in r["junk_ranges"], r["junk_ranges"]


def test_call_next_is_fake_call():
    # call $+5(e8 00000000 @0x1000 → 目标 0x1005 == 下一条)→ 取 EIP 花招,非真 call。
    blob = bytes.fromhex("e800000000") + bytes.fromhex("c3")   # call 0x1005 ; ret@0x1005
    r = deflower_bytes(blob, 0x1000, "x86_64")

    assert r["ok"] is True
    assert any(p["kind"] == "call_next" for p in r["junk_patterns"]), r["junk_patterns"]
    # fallthrough(=call 目标)处的 ret 被到达
    assert "0x1005  ret" in r["cleaned_disasm"], r["cleaned_disasm"]


def test_push_ret_is_jmp():
    # push 0x1008 ; ret → 等价 jmp 0x1008,跳过中间 2 字节 junk。
    blob = (bytes.fromhex("6808100000")      # 0x1000 push 0x1008
            + bytes.fromhex("c3")            # 0x1005 ret(与 push 合成 jmp)
            + bytes.fromhex("9090")          # 0x1006 junk(被跳过)
            + bytes.fromhex("90")            # 0x1008 nop(真实,跳转落点)
            + bytes.fromhex("c3"))           # 0x1009 ret
    r = deflower_bytes(blob, 0x1000, "x86_64")

    assert r["ok"] is True
    assert any(p["kind"] == "push_ret" and p["target"] == "0x1008"
               for p in r["junk_patterns"]), r["junk_patterns"]
    assert ["0x1006", "0x1008"] in r["junk_ranges"], r["junk_ranges"]


def test_arch_32bit():
    # arch 不含 '64' → 走 32 位反汇编;规则同样生效。
    blob = (bytes.fromhex("31c0") + bytes.fromhex("7402") + bytes.fromhex("e8cc")
            + bytes.fromhex("b8efbeadde") + bytes.fromhex("c3"))
    r = deflower_bytes(blob, 0x1000, "x86")

    assert r["arch"] == "x86_32"
    assert any(p["kind"] == "xor_zf_je" for p in r["junk_patterns"])


def test_normal_xor_not_flagged():
    # xor eax,eax 后不是 je → 普通清零,不当花指令,正常留在 cleaned。
    blob = bytes.fromhex("31c0") + bytes.fromhex("c3")   # xor eax,eax ; ret
    r = deflower_bytes(blob, 0x1000, "x86_64")

    assert r["junk_patterns"] == []
    assert "xor eax, eax" in r["cleaned_disasm"]
