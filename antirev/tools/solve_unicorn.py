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
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32, UC_ARCH_ARM64, UC_MODE_ARM,
                         UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED)
    from unicorn.x86_const import *

    p = json.loads(sys.argv[1])
    data = open(p["binary"], "rb").read()

    # —— 把二进制可加载段映射进 unicorn;顺带解析导入表(GOT/IAT 槽→符号名),供 F1 libc hook ——
    def load_segments(uc):
        segs = []
        imports = {}                 # F1:GOT/IAT 槽 VA → libc 符号名
        if data[:2] == b"MZ":        # PE
            import pefile
            pe = pefile.PE(p["binary"], fast_load=True)
            base = pe.OPTIONAL_HEADER.ImageBase
            for s in pe.sections:
                segs.append((base + s.VirtualAddress, s.get_data()))
            try:
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
                for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                    for imp in entry.imports:
                        if imp.name and imp.address:
                            imports[int(imp.address)] = imp.name.decode("latin1")
            except Exception:
                pass
        elif data[:4] == b"\x7fELF":  # ELF
            from elftools.elf.elffile import ELFFile
            from elftools.elf.relocation import RelocationSection
            import io
            elf = ELFFile(io.BytesIO(data))
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_LOAD":
                    segs.append((seg.header.p_vaddr, seg.data()))
            try:                      # .rela.plt/.rela.dyn:r_offset=GOT槽, r_info_sym→.dynsym 符号名
                for sec in elf.iter_sections():
                    if not isinstance(sec, RelocationSection):
                        continue
                    symtab = elf.get_section(sec["sh_link"])
                    if symtab is None:
                        continue
                    for r in sec.iter_relocations():
                        si = r["r_info_sym"]
                        if si == 0:
                            continue
                        nm = symtab.get_symbol(si).name
                        if nm:
                            imports[int(r["r_offset"])] = nm   # 非PIE:r_offset=绝对GOT地址(基址0x400000与IDA一致)
            except Exception:
                pass
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
        return imports

    def _norm_arch(a):   # 命名归一化:x86-64/amd64/x64→x86_64, x86/i386→x86_32(修 2000 传 'x86-64' 连字符被拒)
        a = (a or "x86_64").lower().replace("-", "_")
        if a in ("x86_64", "amd64", "x64", "em64t"): return "x86_64"
        if a in ("x86", "x86_32", "i386", "i686", "ia32", "32"): return "x86_32"
        if a in ("arm64", "aarch64"): return "arm64"
        return a
    arch = _norm_arch(p.get("arch", "x86_64"))
    is32 = (arch == "x86_32")
    if arch == "x86_64":
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
    elif is32:
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
    elif arch == "arm64":
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    else:
        print(json.dumps({"ok": False, "error": f"arch {arch} 暂不支持(仅 x86_64/x86_32/arm64)"})); sys.exit()

    # F1:stdin 游标 / heap arena / libc 输出缓冲
    STDIN = bytes.fromhex(p.get("stdin_hex") or "")
    st_stdin = {"pos": 0}
    libc_out = bytearray()
    HEAP = 0x8000000
    try:
        uc.mem_map(HEAP, 0x100000)
    except Exception:
        pass
    st_heap = {"ptr": HEAP}
    PTRSZ = 4 if is32 else 8
    _imports = load_segments(uc)
    # F1:GOT/IAT 槽改写成 trap page 内 magic 地址(改未映射会触发 MEM_UNMAPPED,改已映射→CODE hook 精确命中查符号名)
    TRAP = 0x9000000
    magic_map = {}
    if _imports:
        try:
            npages = ((len(_imports) * 0x10) + 0xFFF) // 0x1000
            uc.mem_map(TRAP, max(npages, 1) * 0x1000)
            for i, (slot, name) in enumerate(_imports.items()):
                magic = TRAP + i * 0x10
                magic_map[magic] = name
                try:
                    uc.mem_write(slot, magic.to_bytes(PTRSZ, "little"))
                except Exception:
                    pass
        except Exception:
            pass
    # 栈(32位用低地址空间,避免超出 32 位寻址)
    STACK = 0x70000000 if is32 else 0x7000000000
    uc.mem_map(STACK - 0x100000, 0x200000)
    if arch == "x86_64":
        uc.reg_write(UC_X86_REG_RSP, STACK)
        uc.reg_write(UC_X86_REG_RBP, STACK)
    elif is32:
        uc.reg_write(UC_X86_REG_ESP, STACK)
        uc.reg_write(UC_X86_REG_EBP, STACK)
    # scratch 缓冲区(高层封装 emulate_function 放输入用)
    try:
        uc.mem_map(0x1000000, 0x100000)
    except Exception:
        pass
    # FS/GS canary(bug4:很多函数开头 `mov rax, fs:[0x28]` 读栈保护值,不设 FS 段就崩在头几条
    # ——252 的 UcError@47、3446 的 @4 部分源于此)。canary 置 0(够用,不校验回写)。
    if arch == "x86_64":
        try:
            from unicorn.x86_const import UC_X86_REG_FS_BASE
            _TLS = 0x5000000
            uc.mem_map(_TLS, 0x1000); uc.mem_write(_TLS + 0x28, b"\x00" * 8)
            uc.reg_write(UC_X86_REG_FS_BASE, _TLS)
        except Exception:
            pass
    elif is32:
        try:
            from unicorn.x86_const import UC_X86_REG_GS_BASE
            _TLS = 0x5000000
            uc.mem_map(_TLS, 0x1000); uc.mem_write(_TLS + 0x14, b"\x00" * 4)
            uc.reg_write(UC_X86_REG_GS_BASE, _TLS)
        except Exception:
            pass

    # 预写内存(放输入)
    for w in p.get("mem_writes", []):
        uc.mem_write(int(w["addr"]), bytes.fromhex(w["data_hex"]))
    # 设寄存器(传参)
    if arch == "x86_64":
        regmap = {"rdi": UC_X86_REG_RDI, "rsi": UC_X86_REG_RSI, "rdx": UC_X86_REG_RDX,
                  "rcx": UC_X86_REG_RCX, "r8": UC_X86_REG_R8, "r9": UC_X86_REG_R9,
                  "rax": UC_X86_REG_RAX}
    elif is32:   # 32位:同时接受 64 位名(rdx→edx),这样 emulate_function 的 input_reg 无需改就能用
        regmap = {"eax": UC_X86_REG_EAX, "ebx": UC_X86_REG_EBX, "ecx": UC_X86_REG_ECX,
                  "edx": UC_X86_REG_EDX, "esi": UC_X86_REG_ESI, "edi": UC_X86_REG_EDI,
                  "rax": UC_X86_REG_EAX, "rbx": UC_X86_REG_EBX, "rcx": UC_X86_REG_ECX,
                  "rdx": UC_X86_REG_EDX, "rsi": UC_X86_REG_ESI, "rdi": UC_X86_REG_EDI}
    else:
        regmap = {}
    for r, v in p.get("regs", {}).items():
        if r in regmap:
            uc.reg_write(regmap[r], int(v))

    st = {"n": 0, "last_pc": int(p["start"]), "fail": None, "unhandled": set(), "lastnext": -1}
    # C2.4:反调试桩地址集 / 基本块序追踪(去平坦化) / rdtsc 计时中和
    stub_set = set(int(x, 0) if isinstance(x, str) else int(x) for x in p.get("stub_addrs", []))
    trace_on = bool(p.get("trace_blocks", False))
    bb_seq = []
    # —— F1:libc hook 辅助(调用约定读参 / 手动 ret / 读C串)——
    _A64 = [UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9]
    def _arg(i):
        if arch == "x86_64":
            return uc.reg_read(_A64[i])
        sp = uc.reg_read(UC_X86_REG_ESP)                 # cdecl:[esp]=ret,[esp+4]=arg0
        return int.from_bytes(uc.mem_read(sp + 4 + 4 * i, 4), "little")
    def _ret(val):
        m = 0xFFFFFFFFFFFFFFFF if arch == "x86_64" else 0xFFFFFFFF
        if arch == "x86_64":
            sp = uc.reg_read(UC_X86_REG_RSP); ra = int.from_bytes(uc.mem_read(sp, 8), "little")
            uc.reg_write(UC_X86_REG_RSP, sp + 8); uc.reg_write(UC_X86_REG_RAX, val & m)
            uc.reg_write(UC_X86_REG_RIP, ra)
        else:
            sp = uc.reg_read(UC_X86_REG_ESP); ra = int.from_bytes(uc.mem_read(sp, 4), "little")
            uc.reg_write(UC_X86_REG_ESP, sp + 4); uc.reg_write(UC_X86_REG_EAX, val & m)
            uc.reg_write(UC_X86_REG_EIP, ra)
    def _cstr(ptr, cap=0x2000):
        o = bytearray()
        for k in range(cap):
            c = uc.mem_read(ptr + k, 1)[0]
            if c == 0:
                break
            o.append(c)
        return bytes(o)
    def _libc(name):
        n = name.replace("__isoc99_", "").replace("_IO_", "").split("@")[0]
        if n in ("getchar", "getc", "fgetc"):
            pos = st_stdin["pos"]
            if pos < len(STDIN):
                st_stdin["pos"] = pos + 1; return _ret(STDIN[pos])
            return _ret(-1)                              # EOF
        if n in ("putchar", "fputc"):
            c = _arg(0) & 0xFF; libc_out.append(c); return _ret(c)
        if n == "puts":
            libc_out.extend(_cstr(_arg(0))); libc_out.append(0x0A); return _ret(1)
        if n in ("printf", "__printf_chk", "fprintf", "vprintf", "perror"):
            libc_out.extend(_cstr(_arg(1) if n == "fprintf" else _arg(0))); return _ret(0)
        if n == "read":
            buf, cnt = _arg(1), _arg(2); chunk = STDIN[st_stdin["pos"]:st_stdin["pos"] + cnt]
            uc.mem_write(buf, chunk); st_stdin["pos"] += len(chunk); return _ret(len(chunk))
        if n in ("fgets", "gets"):
            buf = _arg(0); size = (1 << 30) if n == "gets" else _arg(1)
            o = bytearray()
            while len(o) < size - 1 and st_stdin["pos"] < len(STDIN):
                c = STDIN[st_stdin["pos"]]; st_stdin["pos"] += 1; o.append(c)
                if c == 0x0A:
                    break
            if not o:
                return _ret(0)
            o.append(0); uc.mem_write(buf, bytes(o)); return _ret(buf)
        if n in ("scanf", "sscanf"):
            rest = bytes(STDIN[st_stdin["pos"]:]); toks = rest.split()
            if toks:
                dst = _arg(1); tok = toks[0]; uc.mem_write(dst, tok + b"\x00")
                st_stdin["pos"] += rest.find(tok) + len(tok); return _ret(1)
            return _ret(-1)
        if n == "strlen":
            return _ret(len(_cstr(_arg(0))))
        if n in ("memcmp", "strncmp", "bcmp", "strcmp"):
            if n == "strcmp":
                x, y = _cstr(_arg(0)), _cstr(_arg(1))
            else:
                ln = _arg(2); x, y = bytes(uc.mem_read(_arg(0), ln)), bytes(uc.mem_read(_arg(1), ln))
            return _ret(0 if x == y else (1 if x > y else -1))
        if n in ("memcpy", "memmove", "strcpy", "strncpy"):
            dst, src = _arg(0), _arg(1)
            ln = _arg(2) if n in ("memcpy", "memmove", "strncpy") else len(_cstr(src)) + 1
            uc.mem_write(dst, bytes(uc.mem_read(src, ln))); return _ret(dst)
        if n in ("malloc", "calloc", "realloc"):
            sz = _arg(0) * _arg(1) if n == "calloc" else (_arg(1) if n == "realloc" else _arg(0))
            cur = st_heap["ptr"]; st_heap["ptr"] = cur + ((int(sz) + 15) & ~15)
            if n == "calloc":
                try:
                    uc.mem_write(cur, b"\x00" * int(sz))
                except Exception:
                    pass
            return _ret(cur)
        if n in ("free", "__stack_chk_fail", "srand", "setbuf", "setvbuf", "__errno_location", "fflush"):
            return _ret(0)
        if n in ("exit", "_exit", "abort"):
            uc.emu_stop(); return
        st["unhandled"].add(n)
        return _ret(0)                                   # 未知 libc:best-effort ret 0
    def _hook(uc, addr, size, ud):
        st["n"] += 1
        if trace_on and addr != st["lastnext"]:      # 与上条不连续=基本块头(去平坦化:真实执行块序)
            bb_seq.append(hex(addr))
        st["last_pc"] = addr
        st["lastnext"] = addr + size
        if st["n"] > p.get("max_insns", 2_000_000):
            uc.emu_stop(); return
        if addr in stub_set:                          # C2.4:反调试桩地址→返回0(未被调试)+手动ret
            _ret(0); return
        if magic_map and addr in magic_map:
            _libc(magic_map[addr])
    uc.hook_add(UC_HOOK_CODE, _hook)
    if p.get("neutralize", True):                     # C2.4:rdtsc 桩(防计时反调试,6526);天然桩化不影响纯变换
        try:
            from unicorn import UC_HOOK_INSN
            from unicorn.x86_const import UC_X86_INS_RDTSC
            _tsc = {"v": 0x1000}
            def _rdtsc(uc, ud):
                _tsc["v"] += 0x100
                uc.reg_write(UC_X86_REG_RAX if arch == "x86_64" else UC_X86_REG_EAX, _tsc["v"] & 0xFFFFFFFF)
                uc.reg_write(UC_X86_REG_RDX if arch == "x86_64" else UC_X86_REG_EDX, 0)
                return True
            uc.hook_add(UC_HOOK_INSN, _rdtsc, None, 1, 0, UC_X86_INS_RDTSC)
        except Exception:
            pass
    # 诊断:捕获未映射内存访问(最常见崩因:撞到未 hook 的 libc/PLT 调用或未映射数据页),
    # 记录出错地址+当时 PC → 让上层能"补映射/补 hook 再重试",而非只看到无信息的 UcError()
    def _memfail(uc, access, addr, size, value, ud):
        if st["fail"] is None:
            st["fail"] = {"access_addr": addr, "at_pc": st["last_pc"]}
        return False   # 不修复 → 触发异常,但诊断已记录
    try:
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, _memfail)
    except Exception:
        pass

    try:
        uc.emu_start(int(p["start"]), int(p["stop"]), timeout=p.get("timeout_us", 8_000_000))
        out = {"ok": True, "insns": st["n"]}
        if libc_out:
            out["stdout"] = libc_out.decode("latin1", "replace")   # F1:libc 打印捕获(看成功/失败串)
        if st["unhandled"]:
            out["unhandled_libc"] = sorted(st["unhandled"])
        if trace_on:
            out["block_trace"] = bb_seq[:2000]        # C2.4:去平坦化——真实执行的基本块顺序
        if arch == "x86_64":
            out["regs"] = {r: uc.reg_read(regmap[r]) for r in ("rax", "rdi", "rsi", "rdx")}
        elif is32:
            out["regs"] = {r: uc.reg_read(regmap[r]) for r in ("eax", "edx", "esi", "edi")}
        if p.get("read_mem"):
            rm = p["read_mem"]
            out["mem_hex"] = uc.mem_read(int(rm["addr"]), int(rm["size"])).hex()
        print(json.dumps(out))
    except Exception as e:
        err = {"ok": False, "error": repr(e), "insns": st["n"], "fail_pc": hex(st["last_pc"])}
        if st["fail"]:
            err["fail_access"] = hex(st["fail"]["access_addr"])
            err["diag"] = (f"未映射内存访问 @{hex(st['fail']['access_addr'])}(执行到 PC={hex(st['fail']['at_pc'])} 时崩)。"
                           "常见原因:撞到未 hook 的 libc/PLT 调用(getchar/scanf/memcmp/malloc…)或所需数据页未映射。"
                           "对策:把 start→stop 缩到只包纯变换段(不跨 call);或该题依赖 libc,需 stdin/桩方案。")
        if trace_on:
            err["block_trace"] = bb_seq[:2000]           # 崩时也返回已追踪块序(去平坦化仍可用)
        if st["unhandled"]:
            err["unhandled_libc"] = sorted(st["unhandled"])
        print(json.dumps(err))
''')


def _to_int(v):
    return int(v, 0) if isinstance(v, str) else int(v)


def emulate_function(binary, start, stop, input_hex="", input_reg="rdx",
                     read_offset=0, read_size=None, extra_regs=None, arch="x86_64",
                     timeout=None, stdin_hex="", stub_addrs=None, trace_blocks=False) -> dict:
    """高层模拟封装(§让模型能一键跑二进制自身逻辑,绕过花指令/魔改静态复现):
    自动把 input_hex 放进 scratch 缓冲区(0x1000000)、令 input_reg 指向它、从 start 跑到 stop、
    读回缓冲区 [read_offset : read_offset+read_size] 作为输出。模型只需给:跑哪段、喂什么、哪个寄存器指向输入、读回多少。

    典型用法(funnyre 类逐字节变换):emulate_function(start=校验起点, stop=比较处, input_hex="666c61677b"+32字节+"7d",
    input_reg="rdx", read_offset=5, read_size=32) → 返回 output_hex = F(输入内容)。喂 0..255 建表可求逆。
    """
    BUF = 0x1000000
    inp = bytes.fromhex(input_hex) if input_hex else b""
    rs = read_size if read_size is not None else (len(inp) if inp else 0)
    mem_writes = [{"addr": BUF, "data_hex": input_hex}] if input_hex else []
    regs = {}
    if input_hex:
        regs[input_reg] = BUF
    for k, v in (extra_regs or {}).items():
        regs[k] = _to_int(v)
    r = unicorn_emulate(binary, _to_int(start), _to_int(stop), arch=arch, regs=regs,
                        mem_writes=mem_writes,
                        read_mem={"addr": BUF + int(read_offset), "size": int(rs)} if rs else None,
                        timeout=timeout, stdin_hex=stdin_hex,
                        stub_addrs=stub_addrs, trace_blocks=trace_blocks)
    if r.get("ok") and "mem_hex" in r:
        r["output_hex"] = r.pop("mem_hex")   # 更直观:这就是变换后的输出
    return r


def solve_stateless_transform(binary, start, stop, cipher_len, cipher_addr=None,
                              input_reg="rdx", read_offset=None, prefix="", suffix="",
                              arch="x86_64") -> dict:
    """位置无关字节变换求解器(§封装枚举建表+逆推,专治"读输入→逐字节独立变换→memcmp比密文"大类):
    对变换段喂 0..255 建 byte→byte 映射 F,读密文按 F⁻¹ 逆推出 flag,并正向自验。模型只给语义参数,
    工具跑循环——省掉手写 unicorn/建表/逆推(那是模型高频出错、跑去写 raw unicorn 反而更错的地方)。

    - start/stop:    变换代码段。start=格式检查后第一条变换;stop=**call memcmp 那条指令**(跑到它停,变换刚好完成)
    - cipher_len:    比较密文字节数(=变换内容长度,如 32)
    - cipher_addr:   密文地址(memcmp 第二参数)。**不给则自动**:跑到 stop 从 rsi 抓(省模型定位密文)
    - input_reg/read_offset/prefix/suffix: 输入如何摆放。如 flag{...}: prefix='flag{' suffix='}'
      (read_offset 不给则默认 = len(prefix),即变换内容紧跟前缀)
    返回 {ok, flag, verified, cipher} 或 {ok:False, error}。**要求变换位置无关**(每字节独立同一函数),否则报错提示。
    """
    from pwn import ELF
    pfx = prefix.encode() if isinstance(prefix, str) else (prefix or b"")
    sfx = suffix.encode() if isinstance(suffix, str) else (suffix or b"")
    N = int(cipher_len)
    off = int(read_offset) if read_offset is not None else len(pfx)

    def build_F(s):
        """从 start=s 建 byte→byte 表;返回 (F, rsi_at_stop, err)。非双射/UcError → F=None。"""
        F = {}
        rsi = None
        for i in range(0, 256, N):
            seg = list(range(i, min(i + N, 256)))
            batch = bytes(seg) + bytes(N - len(seg))
            r = emulate_function(binary, s, _to_int(stop), input_hex=(pfx + batch + sfx).hex(),
                                 input_reg=input_reg, read_offset=off, read_size=N, arch=arch)
            if not r.get("ok"):
                return None, None, str(r.get("error", ""))
            rsi = r.get("regs", {}).get("rsi")
            o = bytes.fromhex(r["output_hex"])
            for j in range(len(seg)):
                F[batch[j]] = o[j]
        if len(set(F.values())) < len(F):
            return None, rsi, "非双射"
        return F, rsi, None

    # 自动校准 start:模型给的地址常差几字节(花指令/看串行),在 start±24 扫描找能产生"位置无关双射"的精确 start
    F = rsi = None
    best = _to_int(start)
    last_err = ""
    for delta in [0] + [d for k in range(1, 25) for d in (k, -k)]:
        F, rsi, err = build_F(_to_int(start) + delta)
        if F:
            best = _to_int(start) + delta
            break
        last_err = err
    if not F:
        return {"ok": False, "error": f"start 附近±24 未找到位置无关双射变换(末错:{last_err[:60]})——核对 start(格式检查后第一条变换)/stop(call memcmp 前)"}

    # 密文:给了直接用;否则用双射运行时抓到的 rsi(=memcmp 第二参数,需 stop 恰为 call memcmp 处)
    ca = _to_int(cipher_addr) if cipher_addr is not None else rsi
    if not ca:
        return {"ok": False, "error": "未拿到密文地址:请给 cipher_addr(=memcmp 第二参数, disasm 里 mov esi/rsi 的立即数, 如 mov esi,4025C0h→0x4025C0)"}
    try:
        C = ELF(str(binary), checksec=False).read(int(ca), N)
    except Exception as e:
        return {"ok": False, "error": f"读密文失败@{hex(int(ca))}: {e!r}"}

    Finv = {v: k for k, v in F.items()}
    try:
        content = bytes(Finv[c] for c in C)
    except KeyError as k:
        return {"ok": False, "error": f"密文含未见字节 {k}(cipher_addr 可能不对/变换非位置无关)"}
    r = emulate_function(binary, best, _to_int(stop), input_hex=(pfx + content + sfx).hex(),
                         input_reg=input_reg, read_offset=off, read_size=N, arch=arch)  # 正向自验
    verified = bool(r.get("ok") and bytes.fromhex(r["output_hex"]) == C)
    flag = pfx + content + sfx
    return {"ok": True, "flag": flag.decode("latin1"), "verified": verified, "cipher": C.hex(), "start_used": hex(best)}


def unicorn_emulate(binary, start, stop, arch="x86_64", regs=None, mem_writes=None,
                    read_mem=None, max_insns=2_000_000, timeout=None, stdin_hex="",
                    stub_addrs=None, trace_blocks=False, neutralize=True) -> dict:
    params = {"binary": str(binary), "start": int(start), "stop": int(stop), "arch": arch,
              "regs": regs or {}, "mem_writes": mem_writes or [], "read_mem": read_mem,
              "max_insns": int(max_insns), "timeout_us": 8_000_000, "stdin_hex": stdin_hex or "",
              "stub_addrs": stub_addrs or [], "trace_blocks": bool(trace_blocks), "neutralize": neutralize}
    r = run_isolated([sys.executable, "-c", _DRIVER, json.dumps(params)],
                     timeout=timeout or config.ANGR_TIMEOUT)
    if r.timed_out:
        return {"ok": False, "error": "unicorn timeout"}
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except Exception:
        return {"ok": False, "error": (r.stderr or r.stdout)}
