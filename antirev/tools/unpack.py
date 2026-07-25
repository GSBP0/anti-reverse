"""generic_unpack(§5.x 通用脱壳):unicorn 从入口跑到疑似 OEP,dump 内存映像,按内存布局重建 PE。

壳(UPX / 自写加壳器)在运行期把真正的代码解压/解密到别的节区,再跳过去执行(OEP=原始入口点)。
静态反编译只看到壳 stub,看不到真实算法。这里用 CPU 级模拟(unicorn,天然沙箱,§5.2 同源)跑壳自解压:
- hook 内存写:记录本次运行被写过的页(= 被解出来的真实代码所落的页);
- hook 每条指令:一旦 PC 落到"刚被写过、且不在壳入口节区、且已跑够指令数"的页 → 判为 OEP,停;
- dump image_base..最大节尾 的内存,按内存布局重建 PE(每节 PointerToRawData=VirtualAddress),写 <binary>.dump.exe。

局限:纯离线无 Windows loader,壳若靠 LoadLibrary/GetProcAddress/VirtualProtect 重建 IAT,会在 API 调用处崩
(优雅降级 ok False)。成功时 IAT 未修复、导入表可能乱码;此时在 dump 上按 OEP 处代码直接读算法即可(note 已提示)。
经 run_isolated 受管子进程跑(§7.2/§11):带指令上限 + 超时,崩溃/挂死不穿透主循环。
"""
from __future__ import annotations
import json
import os
import sys
import tempfile
import textwrap

from antirev import config
from antirev.isolation.subprocess_runner import run_isolated


# —— 纯函数(可脱环境单测) ——————————————————————————————————————————————
def _looks_like_oep(addr, written_pages: set, entry_sec: tuple, n: int) -> bool:
    """OEP 判据:PC 落到本次运行刚被写过的页(page in written_pages)、且不在壳入口节区
    entry_sec=(lo,hi)、且已执行超过 2000 条指令(越过 stub 初始化噪声) → 疑似 OEP。

    直觉:壳把真码解到别处的页(那些页被写过),初始化几百上千条后 jmp 过去正式执行 —— 那一跳就是 OEP。
    入口节区里执行的都是壳自身(自解压循环常会自改写 stub 页),故显式排除。
    """
    page = addr & ~0xFFF
    lo, hi = entry_sec
    return (page in written_pages) and not (lo <= addr < hi) and (n > 2000)


def rebuild_pe(orig_path, image: bytes, oep: int, out_path) -> dict:
    """把 dump 出的内存映像 image(下标 = RVA,image[0] 对应 ImageBase)重建成可再分析的 PE:
    - OPTIONAL_HEADER.AddressOfEntryPoint = oep - ImageBase;
    - 每节 PointerToRawData = VirtualAddress、SizeOfRawData = Misc_VirtualSize(内存对齐布局,offset==RVA);
    - 节 raw 数据从 image 按 VirtualAddress 取。

    返回 {"ok":True,"out":out_path} 或 {"ok":False,"error":...}(异常优雅降级,绝不抛穿)。
    """
    try:
        import pefile
        pe = pefile.PE(str(orig_path))
        base = pe.OPTIONAL_HEADER.ImageBase
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = (int(oep) - base) & 0xFFFFFFFF
        for s in pe.sections:
            s.PointerToRawData = s.VirtualAddress
            s.SizeOfRawData = s.Misc_VirtualSize
        soh = pe.OPTIONAL_HEADER.SizeOfHeaders
        # 只取头部区(含改过的节表);节体自己按 image 铺,不依赖 pe.write() 的节体
        header = bytes(pe.write())[:soh]
        secs = [(s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData) for s in pe.sections]
        pe.close()

        total = max([soh] + [ptr + vsz for (_va, vsz, ptr) in secs])
        out = bytearray(total)
        out[:len(header)] = header
        for (va, vsz, ptr) in secs:
            chunk = bytes(image[va: va + vsz])
            out[ptr: ptr + len(chunk)] = chunk
        with open(out_path, "wb") as f:
            f.write(out)
        return {"ok": True, "out": str(out_path)}
    except Exception as e:
        return {"ok": False, "error": repr(e)}


# —— unicorn 脱壳驱动(经 run_isolated 在受管子进程跑) ——————————————————————————
# 与 solve_unicorn._DRIVER 同范式:load_segments + 栈/canary + JSON-on-last-line。
# OEP 判据内联(与 _looks_like_oep 逻辑一致;驱动是独立 -c 脚本,不便 import 主模块)。
_UNPACK_DRIVER = textwrap.dedent(r'''
    import sys, json
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32,
                         UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_UNMAPPED)
    from unicorn.x86_const import *
    import pefile

    p = json.loads(sys.argv[1])
    data = open(p["binary"], "rb").read()
    if data[:2] != b"MZ":
        print(json.dumps({"ok": False, "error": "generic_unpack 仅支持 PE(MZ 头)"})); sys.exit()

    pe = pefile.PE(p["binary"], fast_load=True)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    entry = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
    machine = pe.FILE_HEADER.Machine

    _a = p.get("arch")
    is64 = (machine == 0x8664) if _a is None else (str(_a).lower().replace("-", "_") in ("x86_64", "amd64", "x64"))
    uc = Uc(UC_ARCH_X86, UC_MODE_64 if is64 else UC_MODE_32)

    def _map(addr, size):
        page = addr & ~0xFFF
        sz = ((addr + size - page + 0xFFF) & ~0xFFF)
        try:
            uc.mem_map(page, max(sz, 0x1000))
        except Exception:
            pass

    # —— 节区边界 + 入口节区(壳 stub 所在节,判 OEP 时排除),同时铺满段 ——
    entry_lo = entry_hi = 0
    secs = []                      # [(va, vsz, blob)] va 为绝对地址
    max_end = image_base
    for s in pe.sections:
        va = image_base + s.VirtualAddress
        vsz = max(s.Misc_VirtualSize, s.SizeOfRawData, 0x1000)
        secs.append((va, vsz, s.get_data()))
        if va <= entry < va + vsz:
            entry_lo, entry_hi = (va & ~0xFFF), ((va + vsz + 0xFFF) & ~0xFFF)
        max_end = max(max_end, va + vsz)

    soh = pe.OPTIONAL_HEADER.SizeOfHeaders          # 部分 stub 读自身 PE 头
    _map(image_base, max(soh, 0x1000)); uc.mem_write(image_base, data[:soh])
    for va, vsz, blob in secs:
        _map(va, vsz)
        try:
            uc.mem_write(va, blob)
        except Exception:
            pass

    # 栈 + FS/GS canary(照 solve_unicorn:很多 prologue 读 fs:[0x28]/gs:[0x14],不设就崩在头几条)
    STACK = 0x7000000000 if is64 else 0x70000000
    _map(STACK - 0x100000, 0x200000)
    if is64:
        uc.reg_write(UC_X86_REG_RSP, STACK); uc.reg_write(UC_X86_REG_RBP, STACK)
        try:
            from unicorn.x86_const import UC_X86_REG_FS_BASE
            _TLS = 0x5000000; uc.mem_map(_TLS, 0x1000)
            uc.mem_write(_TLS + 0x28, b"\x00" * 8); uc.reg_write(UC_X86_REG_FS_BASE, _TLS)
        except Exception:
            pass
    else:
        uc.reg_write(UC_X86_REG_ESP, STACK); uc.reg_write(UC_X86_REG_EBP, STACK)
        try:
            from unicorn.x86_const import UC_X86_REG_GS_BASE
            _TLS = 0x5000000; uc.mem_map(_TLS, 0x1000)
            uc.mem_write(_TLS + 0x14, b"\x00" * 4); uc.reg_write(UC_X86_REG_GS_BASE, _TLS)
        except Exception:
            pass

    written = set()
    st = {"n": 0, "oep": None, "last": entry}
    MAXI = int(p.get("max_insns", 10_000_000))

    def _code(uc, addr, size, ud):
        st["n"] += 1
        st["last"] = addr
        # OEP 判据(与主模块 _looks_like_oep 一致):被写过的页 + 不在入口节区 + 越过初始化
        if st["oep"] is None and ((addr & ~0xFFF) in written) and not (entry_lo <= addr < entry_hi) and st["n"] > 2000:
            st["oep"] = addr
            uc.emu_stop()
        elif st["n"] > MAXI:
            uc.emu_stop()

    def _wr(uc, access, addr, size, value, ud):
        written.add(addr & ~0xFFF)

    def _unmapped(uc, access, addr, size, value, ud):
        return False   # 不修复 → 触发异常;下面 except 按是否已定位 OEP 决定成败

    uc.hook_add(UC_HOOK_CODE, _code)
    uc.hook_add(UC_HOOK_MEM_WRITE, _wr)
    try:
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, _unmapped)
    except Exception:
        pass

    def _dump_and_report():
        img = bytearray(max_end - image_base)
        for va, vsz, _blob in secs:
            try:
                img[va - image_base: va - image_base + vsz] = uc.mem_read(va, vsz)
            except Exception:
                pass
        open(p["dump_bin"], "wb").write(bytes(img))
        print(json.dumps({"ok": True, "oep": st["oep"], "image_base": image_base,
                          "size": len(img), "insns": st["n"]}))

    UNTIL = (1 << (64 if is64 else 32)) - 0x1000   # 不设自然终点,只靠 hook/超时/异常停
    try:
        uc.emu_start(entry, UNTIL, timeout=int(p.get("timeout_us", 60_000_000)))
        if st["oep"] is not None:
            _dump_and_report()
        else:
            print(json.dumps({"ok": False, "insns": st["n"], "last_pc": hex(st["last"]),
                              "error": "跑完/超时仍未定位到 OEP(壳可能自改写入口节内,或依赖 Windows API 重建 IAT,离线无法完成)"}))
    except Exception as e:
        if st["oep"] is not None:
            _dump_and_report()
        else:
            print(json.dumps({"ok": False, "error": repr(e), "insns": st["n"], "last_pc": hex(st["last"]),
                              "diag": "模拟在定位 OEP 前崩溃(常见:壳调用 LoadLibrary/GetProcAddress/VirtualProtect 重建 IAT,"
                                      "纯离线 unicorn 无 loader 无法执行这些调用)。"}))
''')


def generic_unpack(binary, arch=None) -> dict:
    """通用脱壳:unicorn 跑到疑似 OEP → dump 内存 → 重建 PE 写 <binary>.dump.exe。

    返回 {"ok":bool, "oep"?, "out"?, "method":"unicorn-run-to-oep", "iat_fixed":False, "note":...}。
    失败/异常一律优雅降级 ok False(附 note 说明离线限制),绝不抛穿主循环。
    """
    binary = str(binary)
    out_path = binary + ".dump.exe"
    note = ("已跑到疑似OEP并dump重建;在dump文件上重新analyze/ida_decompile。"
            "IAT可能未修复(离线无loader),导入乱码时按OEP处代码直接读算法")
    meta = {"method": "unicorn-run-to-oep", "iat_fixed": False, "note": note}

    try:
        with open(binary, "rb") as f:
            head = f.read(2)
    except Exception as e:
        return {"ok": False, "error": f"读取二进制失败: {e!r}", **meta}
    if head != b"MZ":
        return {"ok": False, "error": "generic_unpack 目前仅支持 PE(MZ 头);其它格式请用别的手段", **meta}

    dump_bin = tempfile.NamedTemporaryFile(prefix="unpack_", suffix=".bin", delete=False).name
    try:
        uni_us = max(5, config.ANGR_TIMEOUT - 10) * 1_000_000
        params = {"binary": binary, "arch": arch, "dump_bin": dump_bin,
                  "max_insns": 10_000_000, "timeout_us": uni_us}
        r = run_isolated([sys.executable, "-c", _UNPACK_DRIVER, json.dumps(params)],
                         timeout=config.ANGR_TIMEOUT)
        if r.timed_out:
            return {"ok": False, "error": "generic_unpack 超时(壳自解压过长或卡在 API 调用)", **meta}
        try:
            res = json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            return {"ok": False, "error": (r.stderr or r.stdout or "无输出")[:400], **meta}
        if not res.get("ok") or res.get("oep") is None:
            return {"ok": False, "error": res.get("error", "未定位到 OEP"), **meta}

        with open(dump_bin, "rb") as f:
            image = f.read()
        oep = int(res["oep"])
        rb = rebuild_pe(binary, image, oep, out_path)
        if not rb.get("ok"):
            return {"ok": False, "error": f"已定位 OEP 但 PE 重建失败: {rb.get('error')}", "oep": hex(oep), **meta}
        return {"ok": True, "oep": hex(oep), "out": out_path, **meta}
    finally:
        try:
            os.unlink(dump_bin)
        except Exception:
            pass
