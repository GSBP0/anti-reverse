"""逆向解题知识库(补本地模型的认知盲区)。

**可维护**:新增一个知识点,只需往 `_KB` 追加一条 entry(id/title/brief/detail/detect),
三层用法自动生效——无需改任何其它代码:
- `checklist()`   → 常驻精简清单(注入 executor/planner 的 system prompt),各条 brief 汇总
- `inject(...)`   → 触发式即时注入:某条的 detect 命中当前工具结果 → 把该条 detail 贴进 observation
                    (在模型踩坑的当下现场补知识;每条每轮只注一次,避免刷屏)
- `recall(topic)` → 按需取某主题 detail(供 recall_knowledge 工具)

entry 字段:
- id:     稳定短名(recall 用)
- title:  标题
- brief:  一行精简线索(进常驻清单)
- detail: 详细知识(触发注入 / recall 时给出)
- detect: fn(tool, args, obs) -> bool;能自动识别征兆的填,填 None 表示只靠常驻清单+recall
"""
from __future__ import annotations
import re


def _text_of(obs) -> str:
    if not isinstance(obs, dict):
        return str(obs)
    return " ".join(str(obs.get(k, "")) for k in ("pseudocode", "disasm", "note", "error", "stdout"))


def _junk_signs(tool, args, obs) -> bool:
    """花指令征兆:hexrays 失败 / positive sp / jz$+1;jnz$+1 跳进指令中间 / call 到超大地址。"""
    if tool not in ("ida_decompile", "ida_disasm"):
        return False
    t = _text_of(obs)
    if not t:
        return False
    return (
        ("hexrays" in t.lower() and "none" in t.lower())          # 反编译失败
        or "positive sp value" in t                                # 栈被搅乱(常见于花指令)
        or (("jz" in t or "jnz" in t) and re.search(r"loc_\w+\+1", t) is not None)  # 跳进指令+1
        or re.search(r"call\s+.*0FFFFFFFF", t) is not None         # call 到 0xFFFFFFFF.. 假地址
    )


def _vm_signs(tool, args, obs) -> bool:
    """VM/字节码征兆:一个函数里超多间接跳转/跳转表(粗判)。"""
    if tool != "ida_decompile" or not isinstance(obs, dict):
        return False
    pc = obs.get("pseudocode") or ""
    # 大量 switch/goto 或 通过表取 handler
    return pc.count("goto ") >= 8 or pc.count("case ") >= 15


def _antidbg_signs(tool, args, obs) -> bool:
    """反调试征兆:IsDebuggerPresent/ptrace/rdtsc 计时等出现在反编译/串里。"""
    t = _text_of(obs).lower()
    return any(k in t for k in ("isdebuggerpresent", "ptrace", "checkremotedebugger",
                                "ntqueryinformationprocess", "outputdebugstring", "rdtsc",
                                "queryperformancecounter"))


def _flatten_signs(tool, args, obs) -> bool:
    """控制流平坦化(OLLVM)征兆:strings/反编译里有 Obfuscator-LLVM 标记。"""
    t = _text_of(obs).lower()
    return "obfuscator-llvm" in t or ".ollvm" in t or "ollvm" in t


def _packed_generic_signs(tool, args, obs) -> bool:
    """analyze 报加壳但非 UPX。"""
    if tool != "analyze" or not isinstance(obs, dict):
        return False
    pk = obs.get("packer", {}) or {}
    hints = pk.get("hints") or []
    txt = " ".join(str(h) for h in hints) if isinstance(hints, list) else str(hints)
    return bool(pk.get("packed_likely")) and "upx" not in txt.lower()


# ============================= 知识库(在此维护/扩充)=============================
_KB = [
    {
        "id": "junk_code",
        "title": "花指令 / 反汇编混淆 (anti-disassembly)",
        "brief": "IDA报'positive sp'/hexrays反编译失败/出现jz$+1;jnz$+1/call到0xFFFF..奇怪地址/指令像被截断 → 反汇编不可信,改 unicorn 模拟跑真实逻辑",
        "detect": _junk_signs,
        "detail": (
            "⚠️ **疑似花指令(反汇编混淆)**。手法:`jz $+1; jnz $+1`(合起来=无条件跳进下一条指令**中间**、跳过一个假 call opcode 0xE8),"
            "让 IDA 从**错误字节边界**解码 → 出假指令/假常量/**假的 call 目标(如 `call 0xFFFFFFFF..`)**。\n"
            "**‼️ 别掉进陷阱**:那个 `call 0xFFFFFFFF..` 是**花指令垃圾、根本不会执行**——**别分析它、别纠结它是什么'神秘函数'**"
            "(纠结它 = 无限空谈到截断)。纯静态扫出的 key 常量里也混着花指令垃圾字节,**不可信**。\n"
            "**正解:①`deflower(start=函数入口)` 去花、拿净化汇编读懂逻辑;②或直接 `emulate_function` 跑真实逻辑**(跟随真实控制流自动跳过花指令)。别再多分析,**下一步就动手**。\n"
            "**具体模板(位置无关的逐字节变换,funnyre类)**:在 run_python 里一个脚本搞定——\n"
            "```\n"
            "from pwn import ELF\n"
            "e=ELF(BINARY,checksec=False)\n"
            "C=e.read(密文地址, N)                 # 比较目标(memcmp的另一参数指向的数据)\n"
            "F={}\n"
            "for run in range(8):\n"
            "    t=bytes(range(run*32,run*32+32))\n"
            "    r=emulate(变换起点, memcmp地址, input_hex=(前缀+t+后缀).hex(), input_reg='rdx', read_offset=前缀长, read_size=N)\n"
            "    o=bytes.fromhex(r['output_hex'])\n"
            "    for j in range(len(t)): F[t[j]]=o[j]\n"
            "Finv={v:k for k,v in F.items()}\n"
            "print(前缀.decode()+bytes(Finv[c] for c in C).decode()+后缀.decode())\n"
            "```\n"
            "(变换起点=格式检查之后第一条变换指令;memcmp地址=最后一段变换之后的 call memcmp 处。)"
        ),
    },
    {
        "id": "stateless_transform",
        "title": "位置无关字节变换(一键求解)",
        "brief": "题型=读输入→对每字节做同样独立变换(xor/add/移位/查表/多轮/花指令)→memcmp比密文 → 别手写unicorn, 用 solve_stateless_transform(给变换段start/stop+密文addr/len+prefix/suffix)自动建表逆推出flag",
        "detect": None,
        "detail": (
            "**位置无关字节变换**:程序读入 flag,对**每个字节做同样的、彼此独立的**变换"
            "(一串 xor K / add K / 移位 / 查表 pass,可能几百段 + 花指令混淆),最后 memcmp 比硬编码密文。\n"
            "**判别**:变换无跨字节依赖(第 i 字节结果只由输入第 i 字节决定)⇒ 整串变换 = 一个固定 byte→byte 双射 F。\n"
            "**一键解法**:用 `solve_stateless_transform` —— 给 ①start=变换区起点(格式检查后第一条变换,**近似即可,工具自动校准±24**) "
            "②stop=**memcmp 的地址**(call memcmp 跳转的目标,如 memcmp@plt 0x4004xx) ③cipher_len ④输入格式 prefix(如 'flag{')/suffix(如 '}')。"
            "cipher_addr **通常不用给**(工具跑到 memcmp 自动抓)。工具自动校准 start + 喂 0..255 建 F 表 + 逆推 + 自验,直接给 flag。**别自己手写 unicorn setup/建表循环——那是最容易出错的地方**。\n"
            "**关键**:stop 用 memcmp 地址最稳(跑到那=变换必然全部完成,对 start 精度不敏感);花指令不用管(unicorn 跟真实控制流自动跳过)。"
        ),
    },
    {
        "id": "decoy",
        "title": "decoy 假 flag / 提示语陷阱",
        "brief": "数据段解出的'you win/correct/带flag前缀'串可能只是提示语,不是比较目标;真目标看 memcmp/strcmp 的另一个参数",
        "detect": None,
        "detail": (
            "数据段里解出的可读串(如 'you get flag!'、'correct!'、甚至长得像 flag 的串)**常常只是成功/失败提示语**,"
            "不是要比对的密文。**真正的比较目标**看 `memcmp/strcmp/cmp` 的**另一个操作数**(通常指向另一段硬编码数据)。"
            "认定某块数据是密文之前,先确认它确实被喂给了比较函数。"
        ),
    },
    {
        "id": "go_dynamic",
        "title": "何时该动态模拟(而非静态复现)",
        "brief": "静态啃不动(花指令/超长运算/魔改算法/VM)→ 别硬复现,emulate 二进制自己的 encrypt/check 函数,喂输入观测输出",
        "detect": None,
        "detail": (
            "**核心策略**:遇到读不懂/易读错的算法(花指令、几百段逐字节运算、魔改密码、VM),"
            "**不要试图用 Python 手工复现**(易抄错、被花指令骗)——直接 **`unicorn_emulate` 跑二进制自身的那段代码**,"
            "把输入喂进去、观测输出。这一步绕过'看懂+精确复现'的全部坑。"
            "位置无关的逐字节变换 ⇒ 枚举 0..255 建 F 表求逆;流密码 ⇒ 跑 encrypt 取 keystream。"
        ),
    },
    {
        "id": "vm_obfusc",
        "title": "VM / 字节码混淆",
        "brief": "大量跳转表+循环取opcode/一堆goto → 是VM,先定位 handler 分发表和字节码数组,再还原每个 handler 语义",
        "detect": _vm_signs,
        "detail": (
            "疑似 **VM 混淆**:程序把逻辑编译成自定义字节码,主循环取 opcode → 查 handler 表 → 执行。\n"
            "**固化工作流(别逐 handler 反复反编译——那是 3521/1886 的坑)**:①定位 **dispatch**(最大跳转扇出的函数)+ **字节码数组**(输入喂进/逐字节取的 data)+ **handler 表**"
            "②`ida_read_bytes` dump 字节码 + 常量表(**越界索引** input[50+i] 而输入才 40 字节 = 硬编码 K/target,静态读它)"
            "③**写 Python 解释器**:拿不准的 handler 用 `emulate_function(start=handler, stop=其ret)` 观测净效果(不手抄)"
            "④跑到最终 CMP 前 `read_mem` 取比较目标(密文)⑤逆变换(位置无关→建 F 表;否则 z3/搜)"
            "⑥Python 解释器输出 vs `emulate` 整段 VM 输出**逐字节对拍**,一致才信(能抓 &0xFF00 这类细节掩码)。"
        ),
    },
    {
        "id": "self_modify",
        "title": "自修改 / 构造函数预处理",
        "brief": "init_array/构造函数(sub_ 在main前跑)可能改数据段(如把密文异或成明文);别只看main,数据要取'运行时'的值",
        "detect": None,
        "detail": (
            "程序常在 **main 之前**用构造函数(.init_array 里的函数)修改数据段——例如把硬编码密文/密钥"
            "异或/解密成运行时才对的值。**静态 read_bytes 读到的是原始值,不是运行时值**。"
            "解法:找到构造函数(通常 score 高、被 init 调用)复现它的变换,或 unicorn 从构造函数跑起再读数据。"
        ),
    },
    {
        "id": "constructed_flag",
        "title": "构造型 flag(公式拼接)",
        "brief": "flag格式含 md5()/sha1()/+/拼接(如 HZCTF{md5(path)+score}) → 程序通常只printf模板串不真算,要你自己按公式算各部分再拼",
        "detect": None,
        "detail": (
            "**构造型 flag**:flag 格式是个**构造公式**,如 `HZCTF{md5(正确路径)+score}`、`flag{sha1(输入)}`、`NSSCTF{base64(key)+序号}`。\n"
            "**关键坑(3692)**:程序通常**只 printf 这个模板字面量、从不实际算 md5/sha1**——别去找不存在的'哈希计算代码',那不在二进制里,是**留给你算的**。\n"
            "**解法**:①把格式拆成各部分(如 `md5(path)` + `score`)②每部分自己求:先解出 x(路径/输入/中间值),再 `run_python` 里 `hashlib.md5(x).hexdigest()`"
            "③**按公式拼接**——`+` 是**字符串拼接不是加法**,连接顺序/分隔符照题目字面(`md5(path)+score` = md5串直接接score串)④组装进 flag 模板提交,别等程序输出成品。"
        ),
    },
    {
        "id": "asm_reading",
        "title": "读汇编的基本功",
        "brief": "汇编里数字都是hex(0x20=32,别当成20!); repne scasb=strlen; lea=算地址; test eax,eax;jz=判零",
        "detect": None,
        "detail": (
            "读汇编易错点:①**所有数字是十六进制**——`cmp rax, 0x20` 是 32 不是 20,`cmp ecx, 0x27` 是 39。"
            "②`repne scasb` + `not rcx` = 求 strlen。③`lea` 是算地址不解引用。④`test eax,eax; jz` = 判是否为 0。"
            "⑤循环次数看 `cmp 计数器, N; jnz`。"
        ),
    },
    {
        "id": "cipher_modified",
        "title": "魔改密码(自定义变体)",
        "brief": "标准库(smart_decrypt)解出乱码 → 可能魔改了delta/轮数/S盒/字符表;优先 unicorn 跑二进制自身的加密函数,别手抄",
        "detect": None,
        "detail": (
            "TEA/XTEA/RC4/base64 等常被魔改:改 delta 常量、改轮数、改 S 盒初始化、改 base64 码表。"
            "`smart_decrypt` 全不像 flag 时:①先确认算法族(看常量:0x9E3779B9=TEA系,256字节表=RC4,64字符表=base64)"
            "②**别手工精确复现**(易错)——`unicorn_emulate` 跑二进制自身的加密/解密函数,喂已知输入取输出/keystream。"
            "③进制/补码/字节序换算别心算(0x61C88647=-0x9E3779B9 这类)——terminal 调 python(hex/int/struct.pack)算。"
        ),
    },
    {
        "id": "anti_debug",
        "title": "反调试检测",
        "brief": "见 IsDebuggerPresent/ptrace/rdtsc计时/CheckRemoteDebugger → 别被'检测到调试器就退出/走假分支'骗;emulate 时 rdtsc 已自动桩,反调试API用 emulate_function(stub_addrs=[..]) 桩成返回0,或 docker_run 实跑",
        "detect": _antidbg_signs,
        "detail": (
            "**反调试**:程序用 IsDebuggerPresent/CheckRemoteDebuggerPresent/NtQueryInformationProcess/ptrace 检测调试器,"
            "或 rdtsc/QueryPerformanceCounter 计时反调试;命中则走假分支/退出/改变解密结果(如 6526 计时陷阱)。\n"
            "**解法**:①静态分析无视反调试分支(它只在'被调试'时走)②`emulate_function` 里 rdtsc/cpuid 已自动桩为常量;"
            "反调试 API 用 `emulate_function(stub_addrs=[反调试thunk地址])` 桩成返回 0(未被调试)③或直接 `docker_run` 实跑(受控沙箱,反调试对它无效)。"
        ),
    },
    {
        "id": "control_flow_flattening",
        "title": "控制流平坦化 (OLLVM)",
        "brief": "strings见Obfuscator-LLVM/一个大函数=分发器+状态变量+魔数大switch → 是平坦化;别顺dispatcher读,emulate_function(trace_blocks=True)拿真实块序,或按state转移还原;不透明谓词(未初始化.bss全局)当常量折叠",
        "detect": _flatten_signs,
        "detail": (
            "**控制流平坦化(OLLVM)**:原函数被拆成一堆基本块,由 dispatcher(大 switch on 状态变量)按'下一状态魔数'调度,"
            "静态顺着读 dispatcher 无意义(块的真实执行序被打乱)。\n"
            "**解法**:①`emulate_function(start=函数入口, stop=返回, trace_blocks=True)` 拿 `block_trace`=真实执行的基本块顺序,据此读真实逻辑"
            "②或识别每块设置的'下一状态'魔数,还原状态转移图③**不透明谓词**(未初始化 .bss 全局做条件,恒真/假,如 749 的 x,y)直接当常量折叠、别分析死分支。"
        ),
    },
    {
        "id": "generic_packer",
        "title": "非 UPX 加壳",
        "brief": "analyze报加壳但不是UPX(高熵/假段名/vsize=1) → 用 unpack_dump(unicorn跑到OEP+dump+重建),在dump上重新分析;假段名UPX0/.vmp先测段熵(≈0是障眼花名)",
        "detect": _packed_generic_signs,
        "detail": (
            "**非 UPX 加壳/高熵**:UPX 用 terminal 调 `upx -d`;其它壳/自定义壳用 `unpack_dump`——unicorn 从入口跑,"
            "壳自解压到别处页后 jmp 过去(那一跳=OEP),dump 内存+重建 PE,之后自动在 dump 上分析。\n"
            "**假段名陷阱**:段名 UPX0/.vmp/.pwdprot 但 Misc_VirtualSize==1、熵≈0 = 障眼花名(6600),别被唬住;真码常在 .text。"
        ),
    },
]
# ==============================================================================


def checklist() -> str:
    """常驻精简清单(进 system prompt)。"""
    lines = ["## 逆向常见陷阱/技巧知识库(务必对照,尤其卡住时)"]
    for e in _KB:
        lines.append(f"- **{e['title'].split('(')[0].strip()}**: {e['brief']}")
    lines.append("(想深入某条用 recall_knowledge 取详细解法)")
    return "\n".join(lines)


def inject(tool, args, obs, seen: set | None = None) -> str:
    """触发式即时注入:命中 detect 的条目返回其 detail(贴进 observation)。seen 去重(每条每轮只注一次)。"""
    out = []
    for e in _KB:
        det = e.get("detect")
        if not det:
            continue
        if seen is not None and e["id"] in seen:
            continue
        try:
            if det(tool, args, obs):
                out.append(f"\n\n[📚知识库·{e['title']}]\n{e['detail']}")
                if seen is not None:
                    seen.add(e["id"])
        except Exception:
            pass
    return "".join(out)


def recall(topic: str) -> dict:
    """按需取某主题详细知识(供 recall_knowledge 工具)。"""
    topic = (topic or "").lower().strip()
    for e in _KB:
        if topic == e["id"] or topic in e["title"].lower() or topic in e["brief"].lower():
            return {"title": e["title"], "detail": e["detail"]}
    return {"error": f"无此主题。可用: {', '.join(e['id'] for e in _KB)}"}
