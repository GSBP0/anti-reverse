"""工具注册表(§14 原生 tool_calls 迁移):18 个执行器工具 + submit_flag 的 OpenAI function schema。

单一事实来源:模型看到的 `tools=[...]` 数组由此生成;执行分派仍在 `react_executor.ReactExecutor._dispatch`。
参数类型据 `_dispatch` 真实解包(如 start/stop 是 "0x.." 字符串,dispatch 内 int(x,0) 转)。
有状态默认参数(solve_angr 的 find/avoid、solve_verify 的 candidate 从 self.state 自动填)**不暴露**给模型。
"""

def _fn(name, description, properties=None, required=None):
    return {"type": "function", "function": {
        "name": name,
        "description": description,
        "parameters": {
            "type": "object",
            "properties": properties or {},
            "required": required or [],
        },
    }}


_STR = {"type": "string"}
_INT = {"type": "integer"}

TOOLS_SCHEMA = [
    _fn("analyze",
        "看格式/架构/位数/导入数/是否加壳。**开局先调它**。无参数。"),
    _fn("floss",
        "提取(含运行时解密的)混淆字符串,静态看不到明文时用。无参数。"),
    _fn("solve_stateless_transform",
        "**位置无关字节变换首选·一键求解**:题型=读输入→对每字节做同样的独立变换(xor/add/移位/查表/多轮/花指令混淆)→memcmp 比密文。"
        "自动校准 start+枚举建表+逆推+自验,返回 {flag,verified}。免手写 unicorn(高频出错处)。要求每字节独立变换。",
        {"start": {**_STR, "description": "变换区起点 0x..(格式检查后第一条变换,近似即可,自动校准±24字节)"},
         "stop": {**_STR, "description": "memcmp 的地址 0x..(call memcmp 跳转目标,如 memcmp@plt)"},
         "cipher_len": {**_INT, "description": "密文长度"},
         "cipher_addr": {**_STR, "description": "密文地址(通常不用给,跑到 memcmp 自动抓)"},
         "input_reg": _STR, "read_offset": _INT, "prefix": {**_STR, "description": "flag 前缀如 flag{"},
         "suffix": _STR, "arch": _STR},
        ["start", "stop", "cipher_len"]),
    _fn("emulate_function",
        "**高层模拟**(位置相关/需自己观测输出时用):遇花指令/魔改/超长运算别静态硬复现,用它跑二进制自身逻辑。"
        "把 input_hex 放缓冲区、令 input_reg 指向它、从 start 跑到 stop、读回缓冲区[read_offset:+read_size]=output_hex。"
        "逐字节求逆:对 input 喂 00..ff 各跑一次建 F 表,flag[i]=F⁻¹(密文[i])。",
        {"start": {**_STR, "description": "起始地址 0x.."},
         "stop": {**_STR, "description": "结束地址 0x.."},
         "input_hex": {**_STR, "description": "输入缓冲区内容(hex)"},
         "input_reg": {**_STR, "description": "指向输入缓冲区的寄存器,如 rdx"},
         "read_offset": _INT, "read_size": _INT,
         "extra_regs": {"type": "object", "description": "额外寄存器设置 {reg: value}"},
         "arch": _STR},
        ["start", "stop"]),
    _fn("unicorn_emulate",
        "底层模拟(需自己设寄存器/内存);一般用 emulate_function 更省事。",
        {"start": {**_STR, "description": "起始地址 0x.."},
         "stop": {**_STR, "description": "结束地址 0x.."},
         "regs": {"type": "object", "description": "寄存器初值 {rdi: .., ..}"},
         "mem_writes": {"type": "array", "description": "预写内存",
                        "items": {"type": "object",
                                  "properties": {"addr": _INT, "data_hex": _STR}}},
         "read_mem": {"type": "object", "description": "读回内存 {addr:.., size:..}",
                      "properties": {"addr": _INT, "size": _INT}},
         "arch": _STR},
        ["start", "stop"]),
    _fn("ida_list_functions",
        "列出函数(名+地址)。找不到某函数名时用它定位。",
        {"filter": {**_STR, "description": "可选:函数名子串过滤"}}),
    _fn("find_key_functions",
        "**无符号(全 sub_)/找不到 main 时先用它**:给所有函数按'像不像校验/加密'打分排序,返回 top-N+每个上榜理由。据此优先反编译高分函数。",
        {"top": {**_INT, "description": "返回前 N 个(默认 12)"}}),
    _fn("ida_decompile",
        "反编译一个函数。返回 pseudocode + data_refs(引用数据的真实地址)+ callees(被调函数名+地址)。"
        "顺 callees 逐层深入(如 main→check_flag)。hexrays 解不了会自动改反汇编(disasm)给你。",
        {"name_or_addr": {**_STR, "description": "函数名或地址,如 main 或 0x401000"}},
        ["name_or_addr"]),
    _fn("ida_disasm",
        "反汇编(出汇编指令)。ida_decompile 报 hexrays 失败/伪代码可疑时用它读真实汇编;"
        "大函数按 outline 段图下钻:给 end=段end 只反汇编 [addr,end) 那一段(免整函数刷屏)。",
        {"name_or_addr": {**_STR, "description": "函数名或地址 0x.."},
         "count": {**_INT, "description": "指令条数(默认 80)"},
         "end": {**_STR, "description": "范围结束地址 0x..(给出则只反汇编 [addr,end),用于 outline 段下钻)"}},
        ["name_or_addr"]),
    _fn("ida_read_bytes",
        "读密文/密钥等原始字节(返回 hex)。**按 data_refs 给的真实地址读,别用伪代码显示名**。",
        {"name_or_addr": {**_STR, "description": "地址 0x.. 或符号名"},
         "size": {**_INT, "description": "读取字节数"}},
        ["name_or_addr", "size"]),
    _fn("run_python",
        "跑解题脚本(有 pwntools/z3/pycryptodome/gmpy2;变量 BINARY 是题目路径)。"
        "魔改算法:先把伪代码核心运算式原样抄成注释、再逐行翻译成 Python(照抄防漏 +1/查表偏移等)。"
        "脚本里可直接用 emulate(start,stop,input_hex=..,input_reg='rdx',read_offset=..,read_size=..) 模拟二进制片段。"
        "也可 from antirev.crypto import smart_decrypt 调内置密码库,别手写标准算法。",
        {"code": {**_STR, "description": "完整可执行的 Python 源码(可多行)"}},
        ["code"]),
    _fn("solve_locate",
        "确定性定位成功/失败分支地址(写回内部 state 的 find/avoid/func_hint)。无参数。"),
    _fn("solve_angr",
        "符号执行求输入(自动用已定位的 find/avoid;需先 solve_locate)。适合'读输入→逐步比较→到达成功分支'型。",
        {"stdin_len": {**_INT, "description": "输入长度(默认 32)"}}),
    _fn("solve_verify",
        "把上一步 solve_angr 的候选喂回二进制自验(候选从内部 state 取)。无参数。"),
    _fn("terminal",
        "**任意本地 shell 命令**(无白名单,bash -c,支持管道/重定向/复合)。可用系统 CLI 补内置工具:"
        "decompyle3/uncompyle6(反编译 pyc)、pyinstxtractor-ng(解 PyInstaller)、upx、binwalk、objdump/nm/readelf、strings|grep 等。"
        "写解题脚本仍优先 run_python;实跑程序验证仍优先 docker_run(受控沙箱)。",
        {"command": {**_STR, "description": "shell 命令行(支持管道/重定向/复合命令)"}},
        ["command"]),
    _fn("recall",
        "重看某步观察的全文(早前步骤只留摘要,需要时按 artifact#N 取回)。大函数分页返回:据结果里的 has_next/total_pages 翻页。",
        {"artifact_id": {**_INT, "description": "artifact 编号"},
         "page": {**_INT, "description": "页码,从 1(默认 1);has_next 为真时 +1 翻下一页"},
         "num": {**_INT, "description": "每页行数(默认 120)"}},
        ["artifact_id"]),
    _fn("recall_knowledge",
        "取某逆向知识点的详细解法(卡住时查:junk_code/vm_obfusc/cipher_modified 等)。",
        {"topic": {**_STR, "description": "知识点主题,如 junk_code"}},
        ["topic"]),
    # —— 阶段二/三 新增工具 ——
    _fn("deflower",
        "**去花指令**(反汇编现 junk 征兆:hexrays失败/positive sp/call到0xFFFF../jz$+1 时用):"
        "从真实控制流重对齐反汇编,剔除不透明跳转(xor r,r;je / je+jne / call$+5 / push;ret)+junk字节,输出净化指令流。"
        "读不懂花指令函数先 deflower;要运行结果用 emulate_function。",
        {"start": {**_STR, "description": "去花起点 0x..(花指令函数入口)"},
         "end": {**_STR, "description": "可选:范围结束 0x.."}, "arch": _STR},
        ["start"]),
    _fn("unpack_dump",
        "通用脱壳(analyze 报加壳但非 UPX/高熵时):unicorn 跑到 OEP+dump内存+重建文件,之后自动在 dump 上分析。可选 arch。",
        {"arch": _STR}),
    _fn("docker_run",
        "**受控 docker 沙箱实跑程序验证候选 flag**(--network=none 只读挂载 内存/进程受限):喂候选 flag 实跑,"
        "回判 verdict=right/wrong/crash/ok——**验证候选 flag 的首选强手段(比正向重算更硬)**;也可 just-run 观察真实输出。docker 缺失自动降级。\n"
        "**两种喂法按题选**:①程序 scanf/read 读输入 → 用 stdin_hex ②程序读命令行参数(main 开头 `cmp edi,2`/用 argv[1]) → 用 argv 传"
        "(**没输出又立刻退出多半是这种**,别只试 stdin)。",
        {"stdin_hex": {**_STR, "description": "喂 stdin 的内容(hex);程序从 stdin 读输入时用"},
         "args": {"type": "array", "items": _STR,
                  "description": "命令行参数列表,如 [\"flag{...}\"];程序从 argv[1] 读 flag 时用"}}),
    _fn("pyinstxtract",
        "PyInstaller 打包的 exe → 提取 .pyc(检测 MEI cookie/PYZ),之后 decompyle3 反编译或 run_python 读 marshal。对当前二进制,无参数。"),
    _fn("dotnet_info",
        ".NET 程序集体检:列方法 + #US 用户字符串堆(flag 模板常在此)。对当前二进制,无参数。看某方法 CIL 用 dotnet_cil。"),
    _fn("dotnet_cil",
        "反汇编某 .NET 方法的 CIL 字节码。",
        {"method": {**_STR, "description": "方法名(从 dotnet_info 的 methods 取)"}},
        ["method"]),
    _fn("data_provenance",
        "**查数据的写交叉引用(SMC护栏)**:信任静态 key/表/密文前查'谁写了这个地址'。有写xref=运行时值≠静态值(构造器/TLS/SMC改过),别信 static_hex,改 emulate 从解密函数跑起再 read_bytes。",
        {"name_or_addr": {**_STR, "description": "数据地址 0x.."}, "size": {**_INT, "description": "字节数(默认16)"}},
        ["name_or_addr"]),
    _fn("deobf_scan",
        "**混淆/保护体检**(判型疑难/疑似反调试/加壳时先跑一次):静态扫出反调试(IsDebuggerPresent/ptrace/rdtsc/计时)、"
        "SMC(VirtualProtect/mprotect/GetProcAddress)。给地址+对策(桩掉/data_provenance/docker_run)。无参数。"),
    _fn("report_unsolved",
        "**诚实退出**(仅当二进制无密文可对:md5(未知输入)/需题面外部输入而题面未给):不逼造假,给'最佳候选+原因'。能算出并验证的题禁用。",
        {"reason": {**_STR, "description": "为何无法唯一确定(如 flag=md5(name+email),题面未给)"},
         "candidate": {**_STR, "description": "可选:目前最接近的候选"}},
        ["reason"]),
    _fn("check_flag",
        "**提交前校验候选 flag(评估 oracle,像 CTF 平台提交看对错)**:算出候选但拿不准/怀疑格式(如算出 LitCTF{} 但预期 NSSCTF{})时,先用它对答案,别自我否定瞎折腾。"
        "回 verdict=correct(确认对→直接 submit_flag)/wrong(不对→换算法/密钥/字节序重解)/no_truth(本题无参考→正向重算或 docker_run 自验)。"
        "**必须先真解出候选再来确认,别拿它枚举爆破**(限次数)。",
        {"flag": {**_STR, "description": "要校验的候选 flag"}},
        ["flag"]),
    _fn("submit_flag",
        "提交最终答案 flag(确信是真解、且已被某工具真实输出过时才调)。**这是终止解题的唯一方式**。",
        {"flag": {**_STR, "description": "最终 flag,如 NSSCTF{...}"}},
        ["flag"]),
]

# 供 decode/校验用的工具名集合
TOOL_NAMES = {t["function"]["name"] for t in TOOLS_SCHEMA}
