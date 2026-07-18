"""IDA idalib 常驻 worker —— 必须由已激活 idalib 的 Python 3.14 解释器运行(见 config.IDA_PY314)。

协议:父进程按行发 JSON 请求 {cmd,args} 到本进程 stdin;本进程把 JSON 响应
{ok, result|error} 按行写到"干净协议通道"(原始 fd1)。IDA/native 的 banner/分析噪声
被重定向到 stderr,绝不污染协议流。这样父进程读到的 stdout 只有纯 JSON。

cmd: list_functions / decompile / strings / xrefs_to / entry_ea / close
"""
import os
import sys
import json

# —— 隔离协议通道:先把原始 fd1 复制出来作协议输出,再把后续所有 fd1 噪声导向 stderr ——
_PROTO_FD = os.dup(1)
os.dup2(2, 1)
_proto = os.fdopen(_PROTO_FD, "w", buffering=1)


def _emit(obj):
    _proto.write(json.dumps(obj) + "\n")
    _proto.flush()


def _resolve_ea(idc, ida_funcs, ida_idaapi, name_or_addr):
    if isinstance(name_or_addr, int):
        ea = name_or_addr
    else:
        s = str(name_or_addr).strip()
        ea = int(s, 16) if s.lower().startswith("0x") else idc.get_name_ea_simple(s)
    if ea == ida_idaapi.BADADDR:
        raise ValueError(f"cannot resolve {name_or_addr!r}")
    f = ida_funcs.get_func(ea)
    return f.start_ea if f else ea


def _resolve_data_ea(idc, ida_idaapi, name_or_addr):
    """解析数据地址(名或十六进制),不做函数归属解析。"""
    if isinstance(name_or_addr, int):
        return name_or_addr
    s = str(name_or_addr).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    ea = idc.get_name_ea_simple(s)
    if ea == ida_idaapi.BADADDR:
        raise ValueError(f"cannot resolve data {name_or_addr!r}")
    return ea


def _ensure_func(ida_funcs, ida_auto, ea):
    """确保 ea 处存在函数。极简/无终止符的二进制,IDA 自动分析可能不建函数;显式补建。"""
    if ida_funcs.get_func(ea) is None:
        ida_funcs.add_func(ea)
        ida_auto.auto_wait()
    return ida_funcs.get_func(ea) is not None


def _handle(cmd, a, mods):
    idautils, idc, ida_funcs, ida_hexrays, ida_idaapi, ida_auto = mods
    if cmd == "list_functions":
        out = []
        for ea in idautils.Functions():
            f = ida_funcs.get_func(ea)
            out.append({"addr": int(ea), "name": idc.get_func_name(ea),
                        "size": int(f.end_ea - f.start_ea) if f else 0})
        return out
    if cmd == "entry_ea":
        import ida_entry
        if ida_entry.get_entry_qty() > 0:
            return {"addr": int(ida_entry.get_entry(ida_entry.get_entry_ordinal(0)))}
        fns = list(idautils.Functions())
        return {"addr": int(fns[0]) if fns else 0}
    if cmd == "decompile":
        import ida_bytes
        ea = _resolve_ea(idc, ida_funcs, ida_idaapi, a["name_or_addr"])
        _ensure_func(ida_funcs, ida_auto, ea)
        cf = ida_hexrays.decompile(ea)
        if cf is None:
            raise RuntimeError("hexrays returned None")
        # 附带函数内引用的数据地址(全局常量/密文/串) —— 伪代码里的 enc_0 显示名未必可解析,
        # 给出真实地址+预览,模型才能按地址 read_bytes(这是"读算法→取常量"流程的关键)
        f = ida_funcs.get_func(ea)
        drefs, dseen = [], set()
        callees, cseen = [], set()   # 调用的函数(名+地址),供模型顺调用图导航(如 main→check_flag)
        if f:
            for item in idautils.FuncItems(f.start_ea):
                for d in idautils.DataRefsFrom(item):
                    if d not in dseen:
                        dseen.add(d)
                        b = ida_bytes.get_bytes(d, 16) or b""
                        drefs.append({"addr": hex(int(d)), "name": idc.get_name(d) or "",
                                      "preview_hex": b.hex(),
                                      "preview_ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in b)})
                for cr in idautils.CodeRefsFrom(item, 0):   # 0: 仅跳转/调用,不含顺序流
                    cfn = ida_funcs.get_func(cr)
                    if cfn and cfn.start_ea == cr and cr != f.start_ea and cr not in cseen:
                        cseen.add(cr)
                        callees.append({"addr": hex(int(cr)), "name": idc.get_func_name(cr)})
        return {"addr": int(ea), "name": idc.get_func_name(ea),
                "pseudocode": str(cf), "data_refs": drefs, "callees": callees}
    if cmd == "strings":
        import re
        rx = re.compile(a["filter"], re.I) if a.get("filter") else None
        out = []
        for s in idautils.Strings():
            v = str(s)
            if rx and not rx.search(v):
                continue
            out.append({"addr": int(s.ea), "value": v})
        return out
    if cmd == "xrefs_to":
        ea = int(a["addr"])
        return [{"frm": int(x.frm), "func": idc.get_func_name(x.frm)}
                for x in idautils.XrefsTo(ea)]
    if cmd == "func_start":
        f = ida_funcs.get_func(int(a["addr"]))
        return {"addr": int(f.start_ea) if f else int(a["addr"]),
                "name": idc.get_func_name(int(a["addr"]))}
    if cmd == "get_bytes":
        import ida_bytes
        ea = _resolve_data_ea(idc, ida_idaapi, a["name_or_addr"])
        size = int(a["size"])
        data = ida_bytes.get_bytes(ea, size) or b""
        return {"addr": int(ea), "size": len(data), "hex": data.hex()}
    raise ValueError(f"unknown cmd {cmd}")


def main():
    if len(sys.argv) < 2:
        _emit({"ok": False, "error": "usage: ida_worker.py <binary>"})
        return
    binary = sys.argv[1]

    import idapro
    try:
        idapro.enable_console_messages(False)
    except Exception:
        pass
    rc = idapro.open_database(binary, True)  # True = 跑自动分析,阻塞至完成
    if rc != 0:
        _emit({"ok": False, "error": f"open_database rc={rc}"})
        return

    import idautils, idc, ida_funcs, ida_hexrays, ida_idaapi, ida_auto, ida_entry
    ida_auto.auto_wait()  # 等自动分析完成(open_database 未必等到底)
    # 极简 ELF 下 idalib 可能不在入口自动建函数,显式确保
    if ida_entry.get_entry_qty() > 0:
        _e = int(ida_entry.get_entry(ida_entry.get_entry_ordinal(0)))
        _ensure_func(ida_funcs, ida_auto, _e)
    try:
        hexrays_ok = bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        hexrays_ok = False
    mods = (idautils, idc, ida_funcs, ida_hexrays, ida_idaapi, ida_auto)
    _emit({"ok": True, "result": {"status": "ready", "hexrays": hexrays_ok}})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            _emit({"ok": False, "error": f"bad request json: {e!r}"})
            continue
        cmd, args = req.get("cmd"), req.get("args", {})
        if cmd == "close":
            _emit({"ok": True, "result": "bye"})
            break
        try:
            _emit({"ok": True, "result": _handle(cmd, args, mods)})
        except Exception as e:
            _emit({"ok": False, "error": f"{cmd} failed: {e!r}"})

    try:
        idapro.close_database(False)
    except Exception:
        pass


if __name__ == "__main__":
    main()
