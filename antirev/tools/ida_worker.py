"""IDA idalib 常驻 worker —— 必须由已激活 idalib 的 Python 3.14 解释器运行(见 config.IDA_PY314)。

协议:父进程按行发 JSON 请求 {cmd,args} 到本进程 stdin;本进程把 JSON 响应
{ok, result|error} 按行写到"干净协议通道"(原始 fd1)。IDA/native 的 banner/分析噪声
被重定向到 stderr,绝不污染协议流。这样父进程读到的 stdout 只有纯 JSON。

cmd: list_functions / decompile / strings / xrefs_to / entry_ea / close
"""
import os
import sys
import json

try:
    from antirev.tools.outline_algo import segment_blocks, score_segment
except Exception:      # ida314-venv 可能无 antirev 包路径 → 按脚本所在目录直导
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from outline_algo import segment_blocks, score_segment

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
                "pseudocode": str(cf), "data_refs": drefs, "callees": callees,
                "fingerprint_feat": _fingerprint(mods, ea), "outline": _outline(mods, ea)}
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
    if cmd == "data_provenance":       # 5.1:SMC护栏——查数据的写交叉引用(谁改了它=运行时值≠静态值)
        import ida_xref, ida_bytes
        ea = _resolve_data_ea(idc, ida_idaapi, a["name_or_addr"]); size = int(a.get("size", 16))
        writers = []
        for off in range(size):
            for x in idautils.XrefsTo(ea + off):
                if x.type == ida_xref.dr_W:
                    writers.append({"frm": hex(int(x.frm)), "func": idc.get_func_name(x.frm)})
        static = ida_bytes.get_bytes(ea, size) or b""
        return {"addr": hex(ea), "size": size, "static_hex": static.hex(),
                "write_xrefs": writers[:20], "smc_suspected": bool(writers)}
    if cmd == "deobf_scan":            # C2.3:混淆/保护体检(反调试/SMC/rdtsc 一次扫全)
        _AD = ("isdebuggerpresent", "checkremotedebugger", "ntqueryinformationprocess",
               "ntsetinformationthread", "ptrace", "outputdebugstring", "queryperformancecounter")
        _SMC = ("virtualprotect", "virtualalloc", "mprotect", "getprocaddress", "loadlibrary")
        antidbg, smc_apis, rdtsc = [], [], []
        for nm in _AD:
            ea = idc.get_name_ea_simple(nm)
            if ea != ida_idaapi.BADADDR:
                antidbg.append({"api": nm, "thunk": hex(int(ea)),
                                "callers": [hex(int(x.frm)) for x in idautils.XrefsTo(ea)][:5]})
        for nm in _SMC:
            if idc.get_name_ea_simple(nm) != ida_idaapi.BADADDR:
                smc_apis.append(nm)
        for f in idautils.Functions():
            for it in idautils.FuncItems(f):
                if (idc.print_insn_mnem(it) or "").lower() in ("rdtsc", "cpuid"):
                    rdtsc.append(hex(int(it)))
            if len(rdtsc) > 20:
                break
        found = bool(antidbg or smc_apis or rdtsc)
        return {"antidebug": antidbg, "smc_apis": smc_apis, "rdtsc_cpuid": rdtsc[:20],
                "hint": ("反调试→emulate_function(stub_addrs=[thunk地址])桩掉 或 docker_run 实跑;"
                         "SMC(VirtualProtect/mprotect)→data_provenance 查写xref+emulate从解密函数跑起再读运行时值;"
                         "rdtsc→emulate 已自动桩") if found else "未见明显反调试/SMC/计时特征"}
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
    if cmd == "disasm":
        # 反汇编兜底(hexrays 失败)/ 局部下钻(带 end 做 [ea,end) 范围)——IDA 总能出汇编。
        # bug2 修复:精确解析地址、**不归函数头**。749 曾给函数内地址 0x400c00 被 _resolve_ea 归到
        # main 头 0x4007e0 → 永远看不到目标、9 连发同一 disasm。只有"给的就是函数头/函数名"才 dump 整函数。
        na = a["name_or_addr"]
        if isinstance(na, int):
            exact = na
        else:
            s = str(na).strip()
            exact = int(s, 16) if s.lower().startswith("0x") else idc.get_name_ea_simple(s)
        if exact == ida_idaapi.BADADDR:
            raise ValueError(f"cannot resolve {na!r}")
        _ensure_func(ida_funcs, ida_auto, exact)
        end = a.get("end")
        if end is not None:   # 范围模式:从精确 ea 反汇编到 end(不再从函数头起)
            end = int(end, 0) if isinstance(end, str) else int(end)
            lines, items, cur = [], [], exact
            while cur != ida_idaapi.BADADDR and cur < end:
                lines.append(f"{cur:#x}  {idc.GetDisasm(cur)}")
                items.append(cur)
                cur = idc.next_head(cur)
            return {"addr": int(exact), "name": idc.get_func_name(exact),
                    "disasm": "\n".join(lines), "callees": [],
                    "fingerprint_feat": _scan_items(mods, items)}
        f = ida_funcs.get_func(exact)
        lines, callees, cseen = [], [], set()
        def _collect_callees(at):   # 解析 call/jmp 立即数目标,供模型顺 call 跟进(如 call _main → 真 main)
            for cr in idautils.CodeRefsFrom(at, 0):
                cfn = ida_funcs.get_func(cr)
                if cfn and cfn.start_ea == cr and cr not in cseen:
                    cseen.add(cr); callees.append({"addr": hex(int(cr)), "name": idc.get_func_name(cr)})
        if f is not None and f.start_ea == exact:   # 给的就是函数头/函数名 → dump 整个函数体(原行为)
            for item in idautils.FuncItems(f.start_ea):
                lines.append(f"{item:#x}  {idc.GetDisasm(item)}")
                _collect_callees(item)
        else:   # 函数内精确地址 或 非函数地址 → 从 exact 起反汇编 count 条(修 bug2:不回退函数头)
            cur, n = exact, int(a.get("count", 80))
            for _ in range(n):
                if cur == ida_idaapi.BADADDR or cur == 0:
                    break
                lines.append(f"{cur:#x}  {idc.GetDisasm(cur)}")
                _collect_callees(cur)
                cur = idc.next_head(cur)
        return {"addr": int(exact), "name": idc.get_func_name(exact),
                "disasm": "\n".join(lines), "callees": callees,
                "fingerprint_feat": _fingerprint(mods, exact), "outline": _outline(mods, exact)}
    if cmd == "outline":
        ea = _resolve_ea(idc, ida_funcs, ida_idaapi, a["name_or_addr"])
        _ensure_func(ida_funcs, ida_auto, ea)
        return _outline(mods, ea, min_insn=a.get("min_insn"))
    if cmd == "score_functions":
        return _score_functions(mods, int(a.get("top", 12)))
    raise ValueError(f"unknown cmd {cmd}")


# 关键函数特征词表(F:stripped 二进制定位校验/加密函数)
_KEY_STR = ("flag", "wrong", "correct", "right", "incorrect", "success", "fail",
            "congrat", "well done", "nice", "good job", "try again", "invalid",
            "password", "please input", "enter", "key")
_INPUT_API = ("scanf", "gets", "fgets", "getchar", "cin", "operator>>", "getline",
              "read", "recv", "readfile", "readconsole", "__isoc99")
_ARITH = ("xor", "add", "sub", "shl", "shr", "sar", "rol", "ror", "mul", "imul",
          "and", "or", "not", "neg", "lea")


_CRT_DENY = ("_start", "__libc_csu_init", "__libc_csu_fini", "__do_global_ctors", "__do_global_dtors",
             "register_tm_clones", "deregister_tm_clones", "frame_dummy", "__stack_chk_fail",
             "_init", "_fini", "__libc_start_main", "__gmon_start__", "maincrtstartup",
             "__security_init_cookie", "_rtc_", "__scrt_", "__cxa_", "__vcrt", "__acrt", "__tmaincrtstartup")


def _score_functions(mods, top):
    """给每个函数按'像不像校验/加密函数'打分(F):main可达+循环+密码运算+比较+flag/对错串+读输入。5.3:CRT降权+真checker信号+stripped找main。"""
    idautils, idc, ida_funcs, ida_hexrays, ida_idaapi, ida_auto = mods
    funcs = [int(e) for e in idautils.Functions()]
    # 1) 调用图 + 每函数指令特征(一趟扫完)
    callees_map, feat = {}, {}
    for fea in funcs:
        f = ida_funcs.get_func(fea)
        if not f:
            continue
        cs = set()
        arith = cmp_ = loops = strrefs = 0
        keystr = inputapi = has_cmpfn = has_throw = False
        for item in idautils.FuncItems(f.start_ea):
            mnem = (idc.print_insn_mnem(item) or "").lower()
            if mnem in _ARITH:
                arith += 1
            elif mnem in ("cmp", "test"):
                cmp_ += 1
            for cr in idautils.CodeRefsFrom(item, 0):      # 仅显式跳转/调用
                cfn = ida_funcs.get_func(cr)
                if cfn and cfn.start_ea != fea and cfn.start_ea == cr:
                    cs.add(cfn.start_ea)
                if f.start_ea <= cr < item:                 # 向后跳=循环回边
                    loops += 1
                nm = (idc.get_func_name(cr) or "").lower()
                if any(x in nm for x in _INPUT_API):
                    inputapi = True
                if any(x in nm for x in ("memcmp", "strcmp", "strncmp", "strncasecmp")):
                    has_cmpfn = True    # 5.3:调比较函数=真 checker 标志
                if any(x in nm for x in ("__cxa_throw", "unwind", "abort")):
                    has_throw = True    # 5.3:对→return/错→throw 经典 checker
            for d in idautils.DataRefsFrom(item):
                sv = idc.get_strlit_contents(d, -1, 0)
                if sv:
                    strrefs += 1
                    if any(k in sv.decode("latin1", "ignore").lower() for k in _KEY_STR):
                        keystr = True
        callees_map[fea] = cs
        feat[fea] = dict(size=int(f.end_ea - f.start_ea), arith=arith, cmp=cmp_,
                         loops=loops, strrefs=strrefs, keystr=keystr, inputapi=inputapi,
                         has_cmpfn=has_cmpfn, has_throw=has_throw)
    # 2) 从 entry/main 出发的可达集(校验/加密函数通常 main 可达)
    import ida_entry
    roots = []
    if ida_entry.get_entry_qty() > 0:
        roots.append(int(ida_entry.get_entry(ida_entry.get_entry_ordinal(0))))
    m = idc.get_name_ea_simple("main")
    if m != ida_idaapi.BADADDR:
        roots.append(int(m))
    elif roots:                        # 5.3:stripped 无 main 符号 → 从 entry 里 lea/push 指到的函数找 main 候选
        for it in list(idautils.FuncItems(roots[0]))[:30]:
            for d in idautils.DataRefsFrom(it):
                cand = ida_funcs.get_func(d)
                if cand and cand.start_ea == d and int(d) not in roots:
                    roots.append(int(d))
    reachable, stack = set(), list(roots)
    while stack:
        x = stack.pop()
        if x in reachable:
            continue
        reachable.add(x)
        stack.extend(callees_map.get(x, ()))
    # 3) 打分 + 上榜理由
    out = []
    for fea, ft in feat.items():
        score, why = 0, []
        if any(c in (idc.get_func_name(fea) or "").lower() for c in _CRT_DENY):  # 5.3:CRT/库函数降权,别盖过真checker
            score -= 12; why.append("CRT/库函数-12")
        if fea in reachable:
            score += 3; why.append("main可达")
        if ft["loops"]:
            score += min(ft["loops"], 3) * 2; why.append(f"循环x{ft['loops']}")
        if ft["arith"] >= 3:
            score += min(ft["arith"] // 3, 4) * 2; why.append(f"密码运算x{ft['arith']}")
        if ft["cmp"]:
            score += min(ft["cmp"], 4); why.append(f"比较x{ft['cmp']}")
        if ft["keystr"]:
            score += 5; why.append("引用flag/对错串")
        elif ft["strrefs"]:
            score += min(ft["strrefs"], 3); why.append(f"串引用x{ft['strrefs']}")
        if ft["inputapi"]:
            score += 3; why.append("读输入")
        if ft.get("has_cmpfn"):            # 5.3:调 memcmp/strcmp = 真 checker 标志
            score += 4; why.append("调memcmp/strcmp")
        if ft.get("has_throw"):            # 5.3:对→return/错→throw 的经典 checker(4052 那种小函数)
            score += 4; why.append("异常分支(对错处理)")
        # 5.3:小函数只在'无cmp+无串+无callee'时才罚(别误伤只throw的小真checker)
        if ft["size"] < 16 and not ft["cmp"] and not ft["strrefs"] and not callees_map.get(fea):
            score -= 3
        if ft["size"] > 4000:
            score -= 2
        out.append({"addr": hex(fea), "name": idc.get_func_name(fea),
                    "size": ft["size"], "score": score, "why": why})
    out.sort(key=lambda r: -r["score"])
    return out[:top]


_XFORM = {"xor", "add", "sub", "shl", "shr", "sar", "rol", "ror",
          "mul", "imul", "and", "or", "not", "neg"}   # 数据变换类(lea/inc/dec 属寻址/计数,非变换)
_O_REG, _O_IMM = 1, 5   # IDA operand types(探索实证:reg=1, imm=5)


def _scan_items(mods, items):
    """扫一段指令 EA 列表抽 feat(整函数 _fingerprint 与段级 _outline 复用同一逻辑)。
    feat 契约:{loops,ops:[[mnem,imm]],cmps,cmp_imms,calls,strs,input,size}。"""
    idautils, idc, ida_funcs, ida_hexrays, ida_idaapi, ida_auto = mods
    items = list(items)
    lo = items[0] if items else 0
    loops = cmps = 0
    ops, opseen = [], set()
    cmp_imms, calls, cseen, strs, sseen = [], [], set(), [], set()
    inputapi = False
    for item in items:
        mnem = (idc.print_insn_mnem(item) or "").lower()
        if mnem in _XFORM:
            # xor reg,reg 是自清零惯用法,非数据变换 → 跳过
            if not (mnem == "xor" and idc.get_operand_type(item, 0) == _O_REG
                    and idc.get_operand_type(item, 1) == _O_REG
                    and idc.get_operand_value(item, 0) == idc.get_operand_value(item, 1)):
                imm = None
                for n in range(3):
                    if idc.get_operand_type(item, n) == _O_IMM:
                        imm = int(idc.get_operand_value(item, n))
                        break
                if (mnem, imm) not in opseen:
                    opseen.add((mnem, imm))
                    ops.append([mnem, imm])
        elif mnem in ("cmp", "test"):
            cmps += 1
            for n in range(3):
                if idc.get_operand_type(item, n) == _O_IMM:
                    v = int(idc.get_operand_value(item, n))
                    if v not in cmp_imms:
                        cmp_imms.append(v)
        for cr in idautils.CodeRefsFrom(item, 0):
            if lo <= cr < item:                  # 向后跳到扫描范围内更早处 = 循环回边
                loops += 1
            cfn = ida_funcs.get_func(cr)
            if cfn and cfn.start_ea == cr and cr != lo:
                nm = idc.get_func_name(cr) or hex(int(cr))
                if nm not in cseen:
                    cseen.add(nm)
                    calls.append(nm)
                if any(x in nm.lower() for x in _INPUT_API):
                    inputapi = True
        for d in idautils.DataRefsFrom(item):
            sv = idc.get_strlit_contents(d, -1, 0)
            if sv:
                s = sv.decode("latin1", "ignore")[:16]
                if s not in sseen:
                    sseen.add(s)
                    strs.append(s)
    return {"loops": loops, "ops": ops, "cmps": cmps, "cmp_imms": cmp_imms,
            "calls": calls, "strs": strs[:6], "input": inputapi, "size": len(items)}


def _fingerprint(mods, ea):
    """整函数指纹:_scan_items 的整函数封装(size 用函数字节大小,保持原语义)。"""
    idautils, idc, ida_funcs, ida_hexrays, ida_idaapi, ida_auto = mods
    f = ida_funcs.get_func(ea)
    if not f:
        return {"loops": 0, "ops": [], "cmps": 0, "cmp_imms": [],
                "calls": [], "strs": [], "input": False, "size": 0}
    feat = _scan_items(mods, list(idautils.FuncItems(f.start_ea)))
    feat["size"] = int(f.end_ea - f.start_ea)
    return feat


_OUTLINE_MIN_BLOCKS = 8
_OUTLINE_MIN_INSN = 40   # 真机调:60 漏掉 funnyre 0x4004c0(57insn 有价值3段);40 兼顾(flagcheck 30 仍排除)


def _outline(mods, ea, min_insn=None):
    """函数分段导航地图:FlowChart→纯tuple blocks→gate→segment_blocks(纯)→段级 feat+score。
    有结构的中大函数才生成(gate:≥40指令 且 ≥8块 且 切出≥2段);min_insn 显式给出则放宽(测试/强制)。否则 None。"""
    idautils, idc, ida_funcs, ida_hexrays, ida_idaapi, ida_auto = mods
    import ida_gdl
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    all_items = list(idautils.FuncItems(f.start_ea))
    n_insn = len(all_items)
    if min_insn is None and n_insn < _OUTLINE_MIN_INSN:
        return None
    blocks = []
    for b in ida_gdl.FlowChart(f):
        items = [it for it in all_items if b.start_ea <= it < b.end_ea]
        calls_after = [int(idc.next_head(it)) for it in items
                       if (idc.print_insn_mnem(it) or "").lower().startswith("call")]
        blocks.append({"start": int(b.start_ea), "end": int(b.end_ea),
                       "succs": [int(s.start_ea) for s in b.succs()],
                       "calls_after": calls_after, "n_insn": len(items)})
    if min_insn is None and len(blocks) < _OUTLINE_MIN_BLOCKS:
        return None
    segs = segment_blocks(blocks, int(f.start_ea), int(f.end_ea))
    if len(segs) < 2:
        return None
    out_segs = []
    for i, s in enumerate(segs):
        items = [it for it in all_items if s["start"] <= it < s["end"]]
        feat = _scan_items(mods, items)
        out_segs.append({"id": i, "start": hex(s["start"]), "end": hex(s["end"]),
                         "n_insn": len(items), "kind": s["kind"],
                         "feat": feat, "score": score_segment(feat, s["kind"]), "core": False})
    core_i = max(range(len(out_segs)), key=lambda j: out_segs[j]["score"])
    out_segs[core_i]["core"] = True
    return {"addr": int(ea), "n_blocks": len(blocks), "n_insn": n_insn, "segments": out_segs}


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
