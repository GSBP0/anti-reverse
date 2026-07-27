"""真正的 flag 校验:基于权威 truth 库(从公开 wp 搜集)做前缀无关比对 + 三态判决。

为什么要这个(R21 回归暴露的评估失灵):
- 旧 `eval.score` 对空 truth 恒 False,把"没有标准答案可比"误判成"答错"(gt_verified 严重低估)。
- NSSCTF 平台收录原题时**改写前缀**(HDCTF/LitCTF/HZCTF → NSSCTF),旧比对因前缀不符把正确解误杀。
- 反过来 `solved`(produced)口径太松,把打印模板串的假解(3692 的假 md5)算成功。

本模块:
- **前缀无关**:比对花括号内容,`HDCTF{x}` 与 `NSSCTF{x}` 判等(收录改写只换前缀)。
- **三态**:correct / wrong / no_truth,让"无答案"与"答错"分开统计,评估不再失真。
- **权威 truth 库**:data/flags_truth.json(pid → 正确 flag),优先于易缺失的 wp 提取。
"""
from __future__ import annotations
import json
import re
from pathlib import Path

_TRUTH_FILE = Path(__file__).resolve().parent.parent / "data" / "flags_truth.json"

_FLAG_RE = re.compile(r"\{(.*)\}", re.S)


def _norm(s: str) -> str:
    """归一化:去首尾空白/反引号、去所有内部空白、转小写(容忍排版噪声)。"""
    return re.sub(r"\s+", "", (s or "").strip().strip("`")).lower()


def _inner(flag: str) -> str:
    """取**最外层**花括号内容做前缀无关比对;无花括号则退回整串归一化。

    用最外层(贪婪 .* )避免嵌套/多花括号时截断,如 flag{a{b}c} → a{b}c。
    """
    m = _FLAG_RE.search(flag or "")
    return _norm(m.group(1)) if m else _norm(flag)


def _unwrap_levels(flag: str, max_depth: int = 3) -> list:
    """逐层剥花括号,返回各层归一化文本 [整串, 第1层内, 第2层内, ...]。

    用于比对时容忍**多包一层前缀**(模型常把原始 flag 再套进 NSSCTF{}:
    `NSSCTF{suctf{Pwn_@_hundred_years}}`),但**不会**把截断的 flag 认成对
    (`NSSCTF{Drink_a_c}` 剥出 `drink_a_c` ≠ `drink_a_cup_of_tea!!`)。
    """
    out, s = [], (flag or "")
    out.append(_norm(s))
    for _ in range(max_depth):
        m = _FLAG_RE.search(s)
        if not m:
            break
        s = m.group(1)
        out.append(_norm(s))
    return [x for x in out if x]


def load_truth(path: Path | None = None) -> dict:
    """读权威 truth 库 {pid: {"flag": str, "aliases": [str], ...}};缺文件返回 {}。"""
    p = path or _TRUTH_FILE
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _truths_for(entry: dict) -> list:
    """从一条 truth 记录取所有可接受答案(主 flag + aliases),过滤空值。"""
    if not entry:
        return []
    out = [entry.get("flag")] + list(entry.get("aliases") or [])
    return [t for t in out if t]


def check(my_flag: str, pid, truth_db: dict | None = None) -> tuple:
    """三态校验单题。返回 (verdict, matched_truth):

    - ("correct", t):my_flag 与某标准答案 t **花括号内容一致**(前缀无关);或整串互相包含。
    - ("wrong", None):该题有标准答案,但 my_flag 对不上(或 my_flag 为空)。
    - ("no_truth", None):该题在 truth 库里没有标准答案,**无法判定**(不计入对错分母)。
    """
    db = truth_db if truth_db is not None else load_truth()
    truths = _truths_for(db.get(str(pid), {}))
    if not truths:
        return ("no_truth", None)
    if not my_flag:
        return ("wrong", None)
    # 逐层剥壳后**精确**比对:前缀无关(收录改写 HDCTF→NSSCTF)、容忍多包一层(NSSCTF{suctf{x}}),
    # 但绝不认截断/子串(NSSCTF{Drink_a_c} 不等于 NSSCTF{Drink_a_cup_of_tea!!})。
    mine = _unwrap_levels(my_flag)
    for t in truths:
        theirs = _unwrap_levels(t)
        if set(mine) & set(theirs):
            return ("correct", t)
    return ("wrong", None)


def verdict_only(my_flag: str, pid, truth_db: dict | None = None) -> str:
    """只要三态字符串(correct/wrong/no_truth),便于统计。"""
    return check(my_flag, pid, truth_db)[0]


def _pid_from_run_id(run_id: str):
    """从 run_id 提题号:eval_r21_3846 → '3846'(取末尾连续数字段);提不到返回 None。"""
    m = re.search(r"(\d+)\s*$", run_id or "")
    return m.group(1) if m else None


def verify_for_run(candidate: str, run_id: str, truth_db: dict | None = None) -> dict:
    """框架内"提交校验 oracle"(像 CTF 平台提交 flag 看对错):从 run_id 提 pid,对权威 truth 库判对错。

    专治"算对了却因格式/预期而自我否定、瞎折腾"(如 3846 解出 LitCTF{} 却怀疑非 NSSCTF{})。
    返回 agent 友好结果 {verdict, advice, matched}:
    - correct:与标准答案一致 → 直接 submit,别再折腾。
    - wrong:不符 → 别提交,换思路重解。
    - no_truth:本题无参考答案(未收录) → 不泄露,引导正向重算/docker_run 硬自验。
    """
    pid = _pid_from_run_id(run_id)
    if not pid:
        return {"verdict": "no_truth", "matched": None,
                "advice": "无法定位题号,校验不了;请正向重算(re-encrypt==密文)或 docker_run 实跑自验后再 submit"}
    v, matched = check(candidate, pid, truth_db)
    advice = {
        "correct": "✓ 与标准答案一致,确认正确——直接 submit_flag 提交,别再折腾(前缀非 NSSCTF 也没关系,收录题保留原前缀)",
        "wrong": "✗ 与标准答案不符,别提交;回查算法/密钥/字节序/轮数,换思路重解",
        "no_truth": "本题无参考答案,校验不了;请正向重算(re-encrypt==密文)或 docker_run 实跑自验后再 submit",
    }[v]
    return {"verdict": v, "advice": advice, "matched": matched if v == "correct" else None}
