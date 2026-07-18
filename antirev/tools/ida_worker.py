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
        ea = _resolve_ea(idc, ida_funcs, ida_idaapi, a["name_or_addr"])
        _ensure_func(ida_funcs, ida_auto, ea)
        cf = ida_hexrays.decompile(ea)
        if cf is None:
            raise RuntimeError("hexrays returned None")
        return {"addr": int(ea), "name": idc.get_func_name(ea), "pseudocode": str(cf)}
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
