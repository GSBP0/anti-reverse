"""辅助分析工具(§5.3):确定性预处理,喂给 Planner 判型 / 供 Executor 脱壳。

设计:file_info/entropy/detect_packer 纯 Python(无外部依赖,始终可用);
unpack_upx 用 upx CLI;floss/binwalk/diec 缺失时优雅降级(返回 ok=False + 原因),不阻塞。
"""
from __future__ import annotations
import math
import shutil
from collections import Counter
from pathlib import Path

from antirev.isolation.subprocess_runner import run_isolated

_PE_MACHINE = {0x8664: "x86-64", 0x14C: "x86", 0xAA64: "ARM64", 0x1C0: "ARM"}
_ELF_MACHINE = {0x3E: "x86-64", 0x03: "x86", 0xB7: "ARM64", 0x28: "ARM", 0x08: "MIPS", 0xF3: "RISC-V"}


def _shannon(b: bytes) -> float:
    if not b:
        return 0.0
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in Counter(b).values())


def file_info(binary) -> dict:
    data = Path(binary).read_bytes()
    info = {"size": len(data), "format": "unknown", "arch": "?", "bits": "?"}
    if data[:2] == b"MZ":
        info["format"] = "PE"
        try:
            import pefile
            pe = pefile.PE(binary, fast_load=True)
            m = pe.FILE_HEADER.Machine
            info["arch"] = _PE_MACHINE.get(m, hex(m))
            info["bits"] = 64 if m in (0x8664, 0xAA64) else 32
            pe.parse_data_directories()
            info["num_imports"] = sum(len(d.imports) for d in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
        except Exception as e:
            info["warn"] = repr(e)[:100]
    elif data[:4] == b"\x7fELF":
        info["format"] = "ELF"
        info["bits"] = 64 if data[4] == 2 else 32
        m = int.from_bytes(data[18:20], "little")
        info["arch"] = _ELF_MACHINE.get(m, hex(m))
        info["stripped"] = b".symtab" not in data
    return info


def entropy(binary, block=4096) -> dict:
    data = Path(binary).read_bytes()
    blocks = [{"offset": i, "entropy": round(_shannon(data[i:i + block]), 3)}
              for i in range(0, len(data), block)]
    high = [b for b in blocks if b["entropy"] > 7.2]
    return {"overall": round(_shannon(data), 3),
            "high_entropy_blocks": len(high), "total_blocks": len(blocks)}


def detect_packer(binary) -> dict:
    data = Path(binary).read_bytes()
    hints = []
    for sig in (b"UPX!", b"UPX0", b"UPX1"):
        if sig in data:
            hints.append("UPX")
            break
    ov = entropy(binary)["overall"]
    if ov > 7.0:
        hints.append(f"高熵({ov}),疑似加壳/加密")
    if shutil.which("diec"):
        r = run_isolated(["diec", str(binary)], timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            hints.append("diec: " + r.stdout.strip()[:300])
    return {"hints": sorted(set(hints)), "packed_likely": bool(hints)}


def unpack_upx(binary, out=None) -> dict:
    if not shutil.which("upx"):
        return {"ok": False, "error": "upx 未安装"}
    out = str(out or (str(binary) + ".unpacked"))
    shutil.copy(binary, out)
    r = run_isolated(["upx", "-d", out], timeout=60)
    if r.returncode == 0:
        return {"ok": True, "out": out}
    Path(out).unlink(missing_ok=True)
    return {"ok": False, "error": (r.stderr or r.stdout)[-300:]}


def floss_strings(binary, min_len=5) -> dict:
    exe = shutil.which("floss")
    if not exe:
        return {"ok": False, "error": "floss 未安装"}
    r = run_isolated([exe, "--minimum-length", str(min_len), "-q", str(binary)], timeout=180)
    if r.timed_out:
        return {"ok": False, "error": "floss timeout"}
    return {"ok": r.returncode == 0, "output": r.stdout[-6000:]}


def binwalk_scan(binary) -> dict:
    if not shutil.which("binwalk"):
        return {"ok": False, "error": "binwalk 未安装"}
    r = run_isolated(["binwalk", str(binary)], timeout=60)
    return {"ok": r.returncode == 0, "output": r.stdout[-3000:]}


def ascii_strings(binary, min_len=5, limit=120) -> list:
    """纯 Python 抽可打印 ASCII 串(供 Planner 预分析,不必起 IDA)。"""
    data = Path(binary).read_bytes()
    out, cur = [], bytearray()
    for byte in data:
        if 32 <= byte < 127:
            cur.append(byte)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    # 去重保序 + 截断
    seen, uniq = set(), []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
        if len(uniq) >= limit:
            break
    return uniq
