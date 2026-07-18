"""solve.unicorn(§5.2):CPU 级模拟执行一段代码(自定义解密循环 / VM handler),取运行结果,
不启动整个程序。天然沙箱、架构无关。用于密码库覆盖不到的**非标准变换**。

在受管子进程跑(§7.2/§11),带指令数上限 + 超时。x86-64 优先(CTF 最常见),可扩展 ARM64。
返回 {ok, regs:{...}, mem_hex?, error?}。
"""
from __future__ import annotations
import json
import sys
import textwrap

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated

_DRIVER = textwrap.dedent(r'''
    import sys, json
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
    from unicorn.x86_const import *

    p = json.loads(sys.argv[1])
    data = open(p["binary"], "rb").read()

    # —— 把二进制可加载段映射进 unicorn ——
    def load_segments(uc):
        segs = []
        if data[:2] == b"MZ":       # PE
            import pefile
            pe = pefile.PE(p["binary"], fast_load=True)
            base = pe.OPTIONAL_HEADER.ImageBase
            for s in pe.sections:
                segs.append((base + s.VirtualAddress, s.get_data()))
        elif data[:4] == b"\x7fELF":  # ELF
            from elftools.elf.elffile import ELFFile
            import io
            elf = ELFFile(io.BytesIO(data))
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_LOAD":
                    segs.append((seg.header.p_vaddr, seg.data()))
        else:
            raise RuntimeError("unsupported binary format")
        for addr, blob in segs:
            page = addr & ~0xFFF
            size = ((addr + len(blob) - page + 0xFFF) & ~0xFFF)
            try:
                uc.mem_map(page, max(size, 0x1000))
            except Exception:
                pass
            uc.mem_write(addr, blob)

    arch = p.get("arch", "x86_64")
    if arch == "x86_64":
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
    elif arch == "arm64":
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    else:
        print(json.dumps({"ok": False, "error": f"arch {arch} 暂不支持"})); sys.exit()

    load_segments(uc)
    # 栈
    STACK = 0x7000000000
    uc.mem_map(STACK - 0x100000, 0x200000)
    if arch == "x86_64":
        uc.reg_write(UC_X86_REG_RSP, STACK)
        uc.reg_write(UC_X86_REG_RBP, STACK)

    # 预写内存(放输入)
    for w in p.get("mem_writes", []):
        uc.mem_write(int(w["addr"]), bytes.fromhex(w["data_hex"]))
    # 设寄存器(传参)
    regmap = {"rdi": UC_X86_REG_RDI, "rsi": UC_X86_REG_RSI, "rdx": UC_X86_REG_RDX,
              "rcx": UC_X86_REG_RCX, "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9,
              "rax": UC_X86_REG_RAX} if arch == "x86_64" else {}
    for r, v in p.get("regs", {}).items():
        if r in regmap:
            uc.reg_write(regmap[r], int(v))

    steps = {"n": 0}
    def _hook(uc, addr, size, ud):
        steps["n"] += 1
        if steps["n"] > p.get("max_insns", 2_000_000):
            uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE, _hook)

    try:
        uc.emu_start(int(p["start"]), int(p["stop"]), timeout=p.get("timeout_us", 8_000_000))
        out = {"ok": True, "insns": steps["n"]}
        if arch == "x86_64":
            out["regs"] = {r: uc.reg_read(regmap[r]) for r in ("rax", "rdi", "rsi", "rdx")}
        if p.get("read_mem"):
            rm = p["read_mem"]
            out["mem_hex"] = uc.mem_read(int(rm["addr"]), int(rm["size"])).hex()
        print(json.dumps(out))
    except Exception as e:
        print(json.dumps({"ok": False, "error": repr(e)[:300], "insns": steps["n"]}))
''')


def unicorn_emulate(binary, start, stop, arch="x86_64", regs=None, mem_writes=None,
                    read_mem=None, max_insns=2_000_000, timeout=None) -> dict:
    params = {"binary": str(binary), "start": int(start), "stop": int(stop), "arch": arch,
              "regs": regs or {}, "mem_writes": mem_writes or [], "read_mem": read_mem,
              "max_insns": int(max_insns), "timeout_us": 8_000_000}
    r = run_isolated([sys.executable, "-c", _DRIVER, json.dumps(params)],
                     timeout=timeout or config.ANGR_TIMEOUT)
    if r.timed_out:
        return {"ok": False, "error": "unicorn timeout"}
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        return {"ok": False, "error": (r.stderr or r.stdout)[-800:]}
