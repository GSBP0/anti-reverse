import json

from antirev.obs.logger import RunLogger


def test_jsonl_records_structured_event(tmp_path):
    lg = RunLogger(run_id="chall_A", log_dir=tmp_path)
    lg.event("tool_call", agent="executor", step=1, tool="ida.decompile",
             args={"name": "main"})
    lines = (tmp_path / "chall_A.jsonl").read_text().splitlines()
    rec = json.loads(lines[0])
    assert rec["type"] == "tool_call"
    assert rec["tool"] == "ida.decompile"
    assert rec["run_id"] == "chall_A"
    assert "ts" in rec and rec["ts"].endswith("Z")
    assert rec["args"] == {"name": "main"}


def test_human_line_appended(tmp_path):
    lg = RunLogger(run_id="chall_A", log_dir=tmp_path)
    lg.human_line("[EXECUTOR][step 1][ACTION] ida.decompile(name='main')")
    lg.human_line("[FLAG] flag{x}")
    text = (tmp_path / "chall_A.log").read_text()
    assert "[EXECUTOR]" in text
    assert "[FLAG] flag{x}" in text


def test_multiple_events_are_appended(tmp_path):
    lg = RunLogger(run_id="r", log_dir=tmp_path)
    lg.event("a", step=1)
    lg.event("b", step=2)
    lines = (tmp_path / "r.jsonl").read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["type"] == "b"
