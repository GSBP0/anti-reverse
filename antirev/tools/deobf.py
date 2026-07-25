"""deobf(去花指令):capstone 递归遍历重对齐,识别并剥离不透明跳转/花指令,还原真实控制流。

花指令(junk/opaque predicate)靠"制造恒真跳转 + 在死路里塞半条指令(常是 0xE8 假 call)"
把线性反汇编带偏——IDA/objdump 顺序扫描会把死路里的字节当真指令,吞掉后面真代码的开头。
本工具不做线性 sweep,而是从 start 出发用 worklist **跟真实控制流**递归遍历:恒真跳转直接跳到
真目标,死路字节永不被解码,于是真实指令自然对齐出来。识别 4 类:
  ① xor r,r ; je/jz T   → ZF 恒 1,无条件跳 T(中间死路常吞假 call)
  ② je T ; jne T        → 两分支同目标,等价无条件跳 T
  ③ call $+5            → imm==下一条地址,不是真 call(取 EIP 花招)
  ④ push imm ; ret      → 等价 jmp imm
纯函数 deflower_bytes(可脱二进制单测);deflower 用 pefile/elftools 把 vaddr→文件字节后调之
(段加载写法参考 solve_unicorn.py 的 load_segments)。要**运行结果**(解出变换值)请用 emulate_function。
"""
from __future__ import annotations

from capstone import (Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32,
                      CS_OP_IMM, CS_OP_REG, CS_GRP_JUMP, CS_GRP_RET)


def _to_int(v):
    return int(v, 0) if isinstance(v, str) else int(v)


# ————————————————————— capstone 小工具 —————————————————————
def _decode_at(md, blob, base, addr):
    """从 blob 里 addr 处解码一条指令(addr 是虚拟地址,base 为 blob[0] 的虚拟地址)。"""
    off = addr - base
    if off < 0 or off >= len(blob):
        return None
    for ins in md.disasm(blob[off:off + 16], addr, count=1):
        return ins
    return None


def _op0_imm(ins):
    return bool(ins.operands) and ins.operands[0].type == CS_OP_IMM


def _imm(ins):
    """分支/立即数的第一操作数;capstone detail 下分支 imm 已是**绝对目标地址**。"""
    if ins.operands and ins.operands[0].type == CS_OP_IMM:
        return ins.operands[0].imm
    return None


def _same_regs(ins):
    """xor r,r 判据:两操作数均寄存器且同一个(如 xor eax,eax → ZF=1)。"""
    ops = ins.operands
    return (len(ops) == 2 and ops[0].type == CS_OP_REG
            and ops[1].type == CS_OP_REG and ops[0].reg == ops[1].reg)


def _is_ret(ins):
    return CS_GRP_RET in ins.groups or ins.mnemonic in (
        "ret", "retn", "retf", "iret", "iretd", "iretq")


def _is_cond_jump(ins):
    """条件跳转:属跳转组但不是无条件 jmp(je/jne/jg/ja/loop/jrcxz…)。"""
    return CS_GRP_JUMP in ins.groups and ins.mnemonic != "jmp"


def _fmt(ins):
    return f"{hex(ins.address)}  {ins.mnemonic} {ins.op_str}".rstrip()


def _complement(intervals, lo, hi):
    """[lo,hi) 内**未被 intervals 覆盖**的空洞(合并重叠后取补),返回 [[s,e],..]。"""
    merged = []
    for s, e in sorted(intervals):
        s, e = max(s, lo), min(e, hi)
        if s >= e:
            continue
        if merged and s <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    gaps, cur = [], lo
    for s, e in merged:
        if s > cur:
            gaps.append([cur, s])
        cur = max(cur, e)
    if cur < hi:
        gaps.append([cur, hi])
    return gaps


# ————————————————————— 核心:纯字节去花 —————————————————————
def deflower_bytes(blob: bytes, base: int, arch: str,
                   want_end=None, max_insns: int = 4000) -> dict:
    """对一段原始字节做递归遍历去花(纯函数,不碰二进制,便于单测)。

    blob     : 起始虚拟地址=base 的连续字节
    base     : blob[0] 的虚拟地址(遍历起点)
    arch     : 含 '64' → 64 位,否则 32 位(x86)
    want_end : 关注区间上界(vaddr);junk_ranges 在 [base, want_end) 内计算(None→整段)
    """
    base = _to_int(base)
    mode = CS_MODE_64 if "64" in str(arch) else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True

    end_blob = base + len(blob)
    visited = set()
    worklist = [base]
    cleaned = {}          # addr -> "addr  mnem op"(净化后真实指令)
    junk_patterns = []
    covered = []          # 已解码指令的字节区间(其补集=junk_ranges)

    def cover(ins):
        covered.append((ins.address, ins.address + ins.size))

    while worklist and len(cleaned) < max_insns:
        addr = worklist.pop()
        if addr in visited or not (base <= addr < end_blob):
            continue
        visited.add(addr)
        ins = _decode_at(md, blob, base, addr)
        if ins is None:
            continue
        cover(ins)
        nxt = ins.address + ins.size
        m = ins.mnemonic

        # —— 规则①:xor r,r ; je/jz T → 无条件跳 T ——
        if m == "xor" and _same_regs(ins):
            j = _decode_at(md, blob, base, nxt)
            if j is not None and j.mnemonic in ("je", "jz"):
                t = _imm(j)
                junk_patterns.append({"kind": "xor_zf_je", "at": hex(j.address),
                                      "target": hex(t) if t is not None else None})
                cleaned[addr] = _fmt(ins)          # xor 有实副作用(清零),保留
                visited.add(j.address)
                cover(j)                           # je 是恒真跳转(死路对齐用),不入 cleaned
                if t is not None:
                    worklist.append(t)
                continue
            # 普通 xor(非花)→ 落到下方顺序处理

        # —— 规则④:push imm ; ret → jmp imm ——
        if m == "push" and _op0_imm(ins):
            r = _decode_at(md, blob, base, nxt)
            if r is not None and _is_ret(r):
                imm = _imm(ins)
                junk_patterns.append({"kind": "push_ret", "at": hex(ins.address),
                                      "target": hex(imm) if imm is not None else None})
                visited.add(r.address)
                cover(r)
                if imm is not None:
                    worklist.append(imm)
                continue

        # —— 规则③:call $+5(imm==下一条)→ 非真 call ——
        if m == "call" and _op0_imm(ins):
            t = _imm(ins)
            if t == nxt:
                junk_patterns.append({"kind": "call_next", "at": hex(ins.address),
                                      "target": hex(nxt)})
                worklist.append(nxt)
                continue
            cleaned[addr] = _fmt(ins)              # 真 call:保留,续 fallthrough(不下钻被调函数)
            worklist.append(nxt)
            continue

        # —— 规则②:je T ; jne T(同目标)→ 无条件跳 T ——
        if m in ("je", "jz"):
            j2 = _decode_at(md, blob, base, nxt)
            if j2 is not None and j2.mnemonic in ("jne", "jnz"):
                t1, t2 = _imm(ins), _imm(j2)
                if t1 is not None and t1 == t2:
                    junk_patterns.append({"kind": "je_jne", "at": hex(ins.address),
                                          "target": hex(t1)})
                    visited.add(j2.address)
                    cover(j2)
                    worklist.append(t1)
                    continue
            # 否则落到下方条件跳转处理

        # —— 真实控制流 ——
        if _is_ret(ins) or m == "hlt":
            cleaned[addr] = _fmt(ins)              # 终止,无后继
        elif m == "jmp":
            cleaned[addr] = _fmt(ins)
            t = _imm(ins)
            if t is not None:                      # 间接 jmp(reg/mem)目标未知 → 此路终止
                worklist.append(t)
        elif _is_cond_jump(ins):
            cleaned[addr] = _fmt(ins)
            t = _imm(ins)
            if t is not None:
                worklist.append(t)
            worklist.append(nxt)                   # 条件跳转:目标 + fallthrough 都可达
        elif m == "call":                          # 间接 call:续 fallthrough
            cleaned[addr] = _fmt(ins)
            worklist.append(nxt)
        else:                                      # 顺序指令
            cleaned[addr] = _fmt(ins)
            worklist.append(nxt)

    range_end = end_blob if want_end is None else min(_to_int(want_end), end_blob)
    gaps = _complement(covered, base, range_end)
    junk_ranges = [[hex(s), hex(e)] for s, e in gaps]
    cleaned_disasm = "\n".join(cleaned[a] for a in sorted(cleaned))
    return {
        "ok": True,
        "arch": "x86_64" if mode == CS_MODE_64 else "x86_32",
        "start": hex(base),
        "reached_insns": len(cleaned),
        "junk_patterns": junk_patterns,
        "cleaned_disasm": cleaned_disasm,
        "junk_ranges": junk_ranges,
        "note": (f"去花:识别{len(junk_patterns)}处不透明跳转/花指令,"
                 "据 cleaned_disasm 读真实逻辑;要运行结果(解出变换值)用 emulate_function"),
    }


# ————————————————————— 外层:从二进制加载 —————————————————————
def _load_image(binary):
    """读二进制,返回 (segments=[(vaddr, data),..], arch)。支持 PE/ELF(x86)。"""
    with open(binary, "rb") as f:
        data = f.read()
    segs = []
    if data[:2] == b"MZ":            # PE
        import pefile
        pe = pefile.PE(str(binary), fast_load=True)
        imgbase = pe.OPTIONAL_HEADER.ImageBase
        for s in pe.sections:
            segs.append((imgbase + s.VirtualAddress, s.get_data()))
        arch = "x86_64" if pe.FILE_HEADER.Machine == 0x8664 else "x86_32"
    elif data[:4] == b"\x7fELF":     # ELF
        import io
        from elftools.elf.elffile import ELFFile
        elf = ELFFile(io.BytesIO(data))
        for seg in elf.iter_segments():
            if seg.header.p_type == "PT_LOAD":
                segs.append((seg.header.p_vaddr, seg.data()))
        arch = "x86_64" if elf.elfclass == 64 else "x86_32"
    else:
        raise RuntimeError("不支持的二进制格式(仅 PE/ELF)")
    return segs, arch


def _read_from(segs, start, end):
    """取包含 start 的段中 [start, end) 的连续字节(end=None → 段尾,但至多 0x4000)。"""
    DEFAULT = 0x4000
    for va, blob in segs:
        if va <= start < va + len(blob):
            off = start - va
            if end is not None:
                return blob[off: off + max(0, end - start)]
            return blob[off: off + DEFAULT]
    return None


def deflower(binary, start, end=None, arch=None) -> dict:
    """从二进制文件的虚拟地址 start 处去花(vaddr→文件字节后调 deflower_bytes)。

    binary : PE/ELF 文件路径      start/end : 虚拟地址(int 或 "0x.." 字符串)
    arch   : 不给则自动判 32/64 位
    """
    try:
        start = _to_int(start)
        end_i = _to_int(end) if end is not None else None
        segs, det_arch = _load_image(binary)
    except Exception as e:
        return {"ok": False, "error": f"加载二进制失败: {e!r}"}
    blob = _read_from(segs, start, end_i)
    if blob is None:
        return {"ok": False, "error": f"起始地址 {hex(start)} 不在任何可加载段内"}
    return deflower_bytes(blob, start, arch or det_arch, want_end=end_i)
