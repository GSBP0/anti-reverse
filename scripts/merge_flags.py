"""合并所有 data/flags_search_*.json(subagent 搜索结果)到权威 truth 库 data/flags_truth.json。

用法:每收到一组 subagent 搜索结果,Write 成 data/flags_search_<组>.json,再跑本脚本增量合并。
- 搜到的 flag(非 null)覆盖库中旧值(公开 wp 比题库自带 wp 更权威)。
- confidence=low/none 或 flag=null 的跳过,不污染库。
"""
import glob
import json
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "data"
TRUTH = DATA / "flags_truth.json"


def main():
    db = json.loads(TRUTH.read_text(encoding="utf-8")) if TRUTH.exists() else {}
    added = 0
    for f in sorted(glob.glob(str(DATA / "flags_search_*.json"))):
        grp = json.loads(Path(f).read_text(encoding="utf-8"))
        for pid, e in grp.items():
            if not e.get("flag"):
                continue  # null / 没搜到,跳过
            # 低置信也入库(带 confidence/source 标注,评估时可按来源分层),只跳过 null
            e.setdefault("aliases", [])
            db[str(pid)] = e
            added += 1
    TRUTH.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"合并 {added} 条搜索结果, 现 truth 库共 {len(db)} 题")
    return db


if __name__ == "__main__":
    main()
