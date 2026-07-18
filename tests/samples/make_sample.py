"""生成一个简单 flag 校验 ELF(x86-64 Linux),纯 Python 逐字节手工汇编 —— 不依赖任何外部
汇编器/编译器/交叉工具链(本机 macOS ARM64 上 pwntools 无 amd64 as、lld 未装),全离线可复现。

程序逻辑(freestanding, 纯 syscall, 无 libc):
  read(0, buf, 17); for i in 17: if (buf[i]^0x37)!=TARGET[i]: write(1,"Wrong\\n",6);exit(1)
  write(1,"Correct\\n",8); exit(0)
其中 TARGET[i] = FLAG[i]^0x37。内嵌 "Correct"/"Wrong" 串 → solve.locate_targets 可定位;
数据用 RIP-relative lea 加载 → IDA 可靠建立 dref,xref 能命中。
"""
from __future__ import annotations
import struct
import sys
from pathlib import Path

FLAG = b"flag{unic0rn_x0r}"        # 17 字节
XOR_KEY = 0x37
TARGET = bytes(b ^ XOR_KEY for b in FLAG)
V = 0x400000                        # 加载基址(非 PIE)
CODE_OFF = 0x78                     # ELF头(64) + 1个phdr(56) = 0x78

assert len(FLAG) == 17


def p32(x): return struct.pack("<I", x & 0xFFFFFFFF)


def build_code():
    """返回 (code_bytes, data_vaddrs)。两遍:先emit占位,再回填跳转rel8与RIP-rel disp32。"""
    code = bytearray()
    labels = {}                 # 代码标签 -> code 内偏移
    jmp_fixups = []             # (rel8字节位置, 目标标签)
    rip_fixups = []             # (disp32起始位置, 数据标签, 指令结束时的code偏移)

    def emit(b): code.extend(b)

    def jshort(op, target):     # 短跳转 op rel8
        emit(bytes([op, 0x00]))
        jmp_fixups.append((len(code) - 1, target))

    def rip_lea(modrm, data_label):  # lea reg,[rip+disp32]; modrm=0x3D(rdi)/0x35(rsi)
        emit(bytes([0x48, 0x8D, modrm]))
        pos = len(code)
        emit(b"\x00\x00\x00\x00")
        rip_fixups.append((pos, data_label, len(code)))

    # read(0, buf@[rsp-0x40], 17)
    emit(b"\x31\xFF")                       # xor edi,edi
    emit(b"\x48\x8D\x74\x24\xC0")           # lea rsi,[rsp-0x40]
    emit(b"\xBA" + p32(17))                 # mov edx,17
    emit(b"\x31\xC0")                       # xor eax,eax
    emit(b"\x0F\x05")                       # syscall
    # 比较循环准备
    emit(b"\x48\x8D\x74\x24\xC0")           # lea rsi,[rsp-0x40]
    rip_lea(0x3D, "target")                 # lea rdi,[rip+target]
    emit(b"\xB9" + p32(17))                 # mov ecx,17
    labels["check"] = len(code)
    emit(b"\x8A\x06")                       # mov al,[rsi]
    emit(b"\x34\x37")                       # xor al,0x37
    emit(b"\x8A\x1F")                       # mov bl,[rdi]
    emit(b"\x38\xD8")                       # cmp al,bl
    jshort(0x75, "wrong")                   # jne wrong
    emit(b"\x48\xFF\xC6")                   # inc rsi
    emit(b"\x48\xFF\xC7")                   # inc rdi
    emit(b"\xFF\xC9")                       # dec ecx
    jshort(0x75, "check")                   # jnz check
    # correct: write(1,msg_ok,8); exit(0)
    emit(b"\xBF" + p32(1))                  # mov edi,1
    rip_lea(0x35, "msg_ok")                 # lea rsi,[rip+msg_ok]
    emit(b"\xBA" + p32(8))                  # mov edx,8
    emit(b"\xB8" + p32(1))                  # mov eax,1
    emit(b"\x0F\x05")                       # syscall
    emit(b"\x31\xFF")                       # xor edi,edi
    emit(b"\xB8" + p32(60))                 # mov eax,60
    emit(b"\x0F\x05")                       # syscall
    labels["wrong"] = len(code)
    emit(b"\xBF" + p32(1))                  # mov edi,1
    rip_lea(0x35, "msg_no")                 # lea rsi,[rip+msg_no]
    emit(b"\xBA" + p32(6))                  # mov edx,6
    emit(b"\xB8" + p32(1))                  # mov eax,1
    emit(b"\x0F\x05")                       # syscall
    emit(b"\xBF" + p32(1))                  # mov edi,1
    emit(b"\xB8" + p32(60))                 # mov eax,60
    emit(b"\x0F\x05")                       # syscall
    emit(b"\x0F\x0B")                       # ud2 (终止符:让 IDA 干净界定函数边界,与数据分开)

    code_len = len(code)
    # 数据紧跟代码;计算各数据虚拟地址
    data_off = CODE_OFF + code_len
    # 每段之间都用 null 分隔,否则 IDA 会把相邻数据(异或后的 target 恰好可打印)连成一个串
    ok_off = data_off + len(TARGET) + 1              # null 分隔 target/msg_ok
    no_off = ok_off + len(b"Correct\n") + 1          # null 分隔 msg_ok/msg_no
    dv = {"target": V + data_off, "msg_ok": V + ok_off, "msg_no": V + no_off}
    # 回填短跳转 rel8
    for pos, tgt in jmp_fixups:
        rel = labels[tgt] - (pos + 1)
        assert -128 <= rel <= 127, f"rel8 out of range for {tgt}: {rel}"
        code[pos] = rel & 0xFF
    # 回填 RIP-relative disp32
    for pos, dlabel, end_off in rip_fixups:
        instr_end_vaddr = V + CODE_OFF + end_off
        disp = dv[dlabel] - instr_end_vaddr
        code[pos:pos + 4] = struct.pack("<i", disp)
    return bytes(code), dv


def build_elf():
    code, _ = build_code()
    data = TARGET + b"\x00" + b"Correct\n\x00" + b"Wrong\n\x00"   # 各段 null 分隔
    image = code + data
    total = CODE_OFF + len(image)
    entry = V + CODE_OFF
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = struct.pack("<16sHHIQQQIHHHHHH", e_ident, 2, 62, 1, entry,
                       64, 0, 0, 64, 56, 1, 0, 0, 0)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, V, V, total, total, 0x1000)
    return ehdr + phdr + image


def _verify_with_capstone(code_bytes):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except Exception:
        print("(capstone 不可用,跳过反汇编校验)")
        return True
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    bad = 0
    for insn in md.disasm(code_bytes, V + CODE_OFF):
        pass
    # 覆盖率检查:capstone 应能线性解码全部代码字节
    decoded = sum(insn.size for insn in md.disasm(code_bytes, V + CODE_OFF))
    print(f"capstone 解码 {decoded}/{len(code_bytes)} 字节")
    return decoded == len(code_bytes)


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("flagcheck")
    code, dv = build_code()
    ok = _verify_with_capstone(code)
    elf = build_elf()
    out.write_bytes(elf)
    out.chmod(0o755)
    print(f"wrote {out} ({len(elf)} bytes); flag = {FLAG.decode()}")
    print(f"数据地址: {{'target': {hex(dv['target'])}, 'msg_ok': {hex(dv['msg_ok'])}, "
          f"'msg_no': {hex(dv['msg_no'])}}}")
    if not ok:
        print("!! capstone 校验未全覆盖,编码可能有误", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
