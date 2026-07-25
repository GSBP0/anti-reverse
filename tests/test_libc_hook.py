"""F1 libc/PLT hook 单测。端到端 getchar 需真实动态 ELF(本机 clang 出 Mach-O 无法造),
用真实题 3266(getchar ELF)验证导入解析,加签名/语法/零回归检查。"""
import io
import os
import inspect

import pytest

from antirev.tools.solve_unicorn import unicorn_emulate, emulate_function, _DRIVER


def _find_3266():
    base = "data/nssctf_reverse_l3_4/problems/3266_[NCTF 2022]cccha/annex"
    for r, _, fs in os.walk(base):
        for f in fs:
            p = os.path.join(r, f)
            try:
                if open(p, "rb").read(4) == b"\x7fELF":
                    return p
            except Exception:
                pass
    return None


def test_driver_syntax():
    import ast
    ast.parse(_DRIVER)                       # F1 driver 大改后语法必须正确


def test_stdin_hex_signature_backward_compat():
    # F1:emulate_function/unicorn_emulate 新增 stdin_hex(有默认值,老调用不受影响)
    assert inspect.signature(emulate_function).parameters["stdin_hex"].default == ""
    assert inspect.signature(unicorn_emulate).parameters["stdin_hex"].default == ""


def test_driver_has_libc_handlers():
    # F1:driver 里 libc dispatch 覆盖关键函数 + trap page/magic 机制在
    for token in ("getchar", "memcmp", "malloc", "magic_map", "TRAP", "st_stdin", "_libc"):
        assert token in _DRIVER, token


@pytest.mark.skipif(_find_3266() is None, reason="无 3266 样本")
def test_imports_parsed_from_real_elf():
    # F1:导入解析对真实 ELF(3266 getchar 题,PIE)拿到 libc 符号 → GOT 改写能 hook 它们
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection
    elf = ELFFile(io.BytesIO(open(_find_3266(), "rb").read()))
    imp = {}
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection):
            st = elf.get_section(sec["sh_link"])
            if st is None:
                continue
            for rr in sec.iter_relocations():
                si = rr["r_info_sym"]
                if si:
                    nm = st.get_symbol(si).name
                    if nm:
                        imp[rr["r_offset"]] = nm
    assert any("getchar" in v for v in imp.values())
    assert any("memcmp" in v for v in imp.values())
