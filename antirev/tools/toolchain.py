"""外部工具链(§阶段三 E2):RSA 分解 / PyInstaller 提取 / .NET 反汇编。
照 analyze_tools 的 shutil.which 优雅降级范式;依赖缺失/非目标格式一律降级、绝不抛。"""
from __future__ import annotations
import math
import shutil
import subprocess
from pathlib import Path


# ——————————————————— PyInstaller 提取(614) ———————————————————
def pyinstxtract(binary) -> dict:
    binp = Path(binary)
    try:
        data = binp.read_bytes()
    except Exception as e:
        return {"ok": False, "error": f"读文件失败: {e}"}
    # PyInstaller 特征:尾部 MEI cookie 魔数,或 PYZ 归档头
    if (b"MEI\x0c\x0b\x0a\x0b\x0e" not in data and b"PYZ\x00" not in data
            and b"pyi" not in data[-8192:].lower() and b"python" not in data[-8192:].lower()):
        return {"ok": False, "error": "未检测到 PyInstaller(无 MEI cookie / PYZ / pyi 特征)"}
    # 用 pyinstxtractor-ng 提取(sys.executable=当前 env 的 python,完整解 PYZ 内用户模块——手撸 PYZ 的 zlib 头对不上)
    import sys as _sys
    binp = binp.resolve()
    exdir = binp.parent / (binp.name + "_extracted")
    try:
        subprocess.run([_sys.executable, "-m", "pyinstxtractor_ng", str(binp)],
                       capture_output=True, text=True, timeout=180, cwd=str(binp.parent))
    except Exception:
        return _carchive_extract(data, binp)     # pyinstxtractor-ng 不可用 → 内置 CArchive 兜底
    if not exdir.exists():
        return _carchive_extract(data, binp)
    # 挑用户模块 pyc(排除 PyInstaller 运行时/bootstrap),decompyle3 反编译出**源码**
    _std = getattr(_sys, "stdlib_module_names", frozenset())   # 标准库顶级包名(os/xml/unittest…)
    def _toppkg(p):    # pyc 的顶级包名(PYZ_extracted 后第一层,或根 pyc 名)——用于整包排除标准库
        parts = p.relative_to(exdir).parts
        for i, seg in enumerate(parts):
            if seg.endswith("_extracted"):
                return parts[i + 1] if i + 1 < len(parts) else p.stem
        return parts[0].replace(".pyc", "") if parts else p.stem
    user_pycs = [p for p in exdir.rglob("*.pyc")
                 if not p.name.startswith(("pyimod", "pyiboot", "pyi_rth"))
                 and _toppkg(p) not in _std and p.stem != "struct"]
    dec3 = str(Path(_sys.executable).parent / "decompyle3")
    decompiled = {}
    # 用户模块(顶级包非标准库)深路径子包优先反编译
    for p in sorted(user_pycs, key=lambda x: -len(x.relative_to(exdir).parts))[:15]:
        try:
            src = subprocess.run([dec3, str(p)], capture_output=True, text=True, timeout=90).stdout
            # 滤掉 decompyle3 的语法树 debug 行(::=/Reduce/invalid by check),只留真源码
            src = "\n".join(l for l in (src or "").splitlines()
                            if not l.lstrip().startswith("#") and "::=" not in l
                            and "Reduce " not in l and "invalid by check" not in l)
            if src.strip():
                # 截断要留标记+取回方式(静默砍源码会让模型按半截逻辑推错)
                decompiled[p.name] = (src if len(src) <= 4000 else
                                      src[:4000] + f"\n# ...[源码共 {len(src)} 字符,此处只给前 4000;"
                                                   f"全文用 terminal: decompyle3 {p}]")
        except Exception:
            pass
    return {"ok": True, "extracted_dir": str(exdir),
            "pyc_files": [str(p) for p in user_pycs[:50]],
            "decompiled": decompiled,
            "note": (f"pyinstxtractor-ng 解 PYZ + decompyle3 反编译了 {len(decompiled)} 个用户模块。"
                     "**主逻辑看 decompiled 里非入口模块的源码**(入口 <名>.py 常只 import、真逻辑在 <名>_core 等);"
                     "没反编译出的 pyc 在 pyc_files,可用 terminal 调 decompyle3 补。")}


def _carchive_extract(data, binp) -> dict:
    """内置 PyInstaller CArchive 提取:MEI cookie→TOC→zlib 解压→抽 .pyc(补头供 decompyle3)。"""
    import struct
    import zlib
    MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"
    cpos = data.rfind(MAGIC)
    if cpos < 0:
        return {"ok": False, "error": "未找到 MEI cookie(非 PyInstaller 或已加壳,先脱壳)"}
    outdir = binp.parent / (binp.stem + "_pyextract")
    # cookie 两种布局:>=2.1 含 64 字节 pylibname(总 88),旧版无(总 24);都试
    for cookie_size in (88, 24):
        try:
            pkg_len, toc_off, toc_len, pyver = struct.unpack("!IIII", data[cpos + 8:cpos + 24])
            pkg_start = cpos + cookie_size - pkg_len
            if pkg_start < 0 or not (0 < toc_off < len(data)) or not (0 < toc_len < len(data)):
                continue
            toc = data[pkg_start + toc_off: pkg_start + toc_off + toc_len]
            entries = _parse_toc(toc)
            if not entries:
                continue
            outdir.mkdir(exist_ok=True)
            saved, pycs = [], []
            for e in entries:
                blob = data[pkg_start + e["pos"]: pkg_start + e["pos"] + e["cmpr"]]
                if e["flag"]:
                    try:
                        blob = zlib.decompress(blob)
                    except Exception:
                        pass
                nm = (e["name"] or "unnamed").replace("\x00", "").replace("/", "_").replace("\\", "_")
                if e["type"] in ("s", "m", "M"):     # 脚本/模块 → .pyc(PyInstaller 剥了头,补回)
                    p = outdir / (nm + ".pyc")
                    p.write_bytes(_pyc_header(pyver, len(blob)) + blob)
                    saved.append(str(p)); pycs.append(str(p))
                elif e["type"] in ("z", "Z"):        # PYZ 归档(内含更多模块 pyc)
                    p = outdir / (nm + ".pyz")
                    p.write_bytes(blob); saved.append(str(p))
            if pycs:
                return {"ok": True, "extracted_dir": str(outdir), "pyver": pyver,
                        "pyc_files": pycs[:50], "all_files": len(saved),
                        "note": f"内置提取 {len(saved)} 项({len(pycs)} 个 .pyc)。主逻辑通常在与程序同名的 .pyc;"
                                f"用 run_python 里 decompyle3 反编译,或 marshal.loads(open(pyc,'rb').read()[16:])"}
        except Exception:
            continue
    return {"ok": False, "error": "CArchive cookie 布局异常,解析失败",
            "hint": "run_python 手解:rfind(b'MEI\\x0c\\x0b\\x0a\\x0b\\x0e'),cookie+8 处 struct.unpack('!IIII')=pkgLen/tocOff/tocLen/pyver"}


def _parse_toc(toc) -> list:
    """解析 CArchive TOC 条目表:每条 entryLen(4)+pos(4)+cmpr(4)+uncmpr(4)+flag(1)+type(1)+name。"""
    import struct
    out, i = [], 0
    while i + 18 <= len(toc):
        (elen,) = struct.unpack("!i", toc[i:i + 4])
        if elen < 18 or i + elen > len(toc):
            break
        pos, cmpr, uncmpr = struct.unpack("!iii", toc[i + 4:i + 16])
        out.append({"pos": pos, "cmpr": cmpr, "uncmpr": uncmpr,
                    "flag": toc[i + 16], "type": chr(toc[i + 17]),
                    "name": toc[i + 18:i + elen].split(b"\x00")[0].decode("latin1", "ignore")})
        i += elen
    return out


def _pyc_header(pyver, size) -> bytes:
    """据 pyver 造 .pyc 16 字节头(magic+bitfield+timestamp+size),供 decompyle3 识别。"""
    import struct
    magics = {36: b"\x33\x0d\x0d\x0a", 37: b"\x42\x0d\x0d\x0a", 38: b"\x55\x0d\x0d\x0a",
              39: b"\x61\x0d\x0d\x0a", 310: b"\x6f\x0d\x0d\x0a", 311: b"\xa7\x0d\x0d\x0a",
              312: b"\xcb\x0d\x0d\x0a"}
    magic = magics.get(pyver, b"\x61\x0d\x0d\x0a")
    return magic + b"\x00\x00\x00\x00" + struct.pack("<I", 0) + struct.pack("<I", size)


# ——————————————————— .NET 反汇编(4232) ———————————————————
def dotnet_info(binary) -> dict:
    try:
        import dnfile
    except Exception:
        return {"ok": False, "error": "dnfile 未安装"}
    try:
        pe = dnfile.dnPE(str(binary))
    except Exception as e:
        return {"ok": False, "error": f"非 .NET 或解析失败: {e}"}
    if not getattr(pe, "net", None):
        return {"ok": False, "error": "非 .NET 程序集"}
    methods = []
    try:
        for m in (pe.net.mdtables.MethodDef or []):
            methods.append({"name": str(getattr(m, "Name", "")),
                            "rva": int(getattr(m, "Rva", 0) or 0)})
    except Exception:
        pass
    us = []
    try:                                    # #US 用户字符串堆(flag 模板常在此)
        heap = pe.net.user_strings
        raw = heap.__data__ if hasattr(heap, "__data__") else b""
        off = 1
        while off < len(raw) and len(us) < 200:
            try:
                item = heap.get_with_size(off)
                s, sz = (item if isinstance(item, tuple) else (item, 0))
                if sz <= 0:
                    break
                if s and str(s).strip():
                    us.append(str(s))
                off += sz
            except Exception:
                break
    except Exception:
        pass
    # 截断必须报总量:模型看不到"还有多少"就会以为这就是全部,漏掉关键方法/字符串
    note = "flag 模板常在 user_strings;看某方法 CIL 用 dotnet_cil(name=方法名)"
    if len(methods) > 300 or len(us) > 200:
        note += (f"。**已截断**:方法 {len(methods)} 个只列前 300、用户串 {len(us)} 条只列前 200"
                 f"——没找到目标就用 terminal 调 ilspycmd/monodis 看全量")
    return {"ok": True, "methods": methods[:300], "user_strings": us[:200],
            "methods_total": len(methods), "user_strings_total": len(us), "note": note}


def dotnet_cil(binary, method) -> dict:
    try:
        import dnfile
        from dncil.cil.body import CilMethodBody
        from dncil.cil.body.reader import CilMethodBodyReaderBase
    except Exception:
        return {"ok": False, "error": "dnfile/dncil 未安装;dotnet_info 已给方法列表与 user_strings(flag 常在此)"}
    try:
        pe = dnfile.dnPE(str(binary))
        target = None
        for m in (pe.net.mdtables.MethodDef or []):
            if str(getattr(m, "Name", "")) == str(method):
                target = m
                break
        if target is None:
            return {"ok": False, "error": f"未找到方法 {method};用 dotnet_info 看方法名"}

        class _R(CilMethodBodyReaderBase):
            def __init__(self, data):
                self._d = data
                self._i = 0

            def read(self, n):
                b = self._d[self._i:self._i + n]
                self._i += n
                return b

            def tell(self):
                return self._i

            def seek(self, i):
                self._i = i
                return self._i

        rva = int(getattr(target, "Rva", 0) or 0)
        off = pe.get_offset_from_rva(rva)
        body = CilMethodBody(_R(pe.__data__[off:off + 4096]))
        lines = [f"{ins.offset:#06x}  {ins.mnemonic} {ins.operand if ins.operand is not None else ''}".rstrip()
                 for ins in body.instructions]
        return {"ok": True, "method": str(method), "cil": "\n".join(lines)}
    except Exception as e:
        return {"ok": False, "error": f"CIL 解析失败: {e};dotnet_info 的 user_strings 常含 flag 模板"}
