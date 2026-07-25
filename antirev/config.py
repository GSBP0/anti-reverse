"""集中配置:端点/路径/超时/内存阈值/关键词表。全文件无副作用,只读常量 + 环境变量覆盖。"""
from __future__ import annotations
import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# —— 模型端点(OpenAI 兼容) ——
MODEL_BASE_URL = os.environ.get("ANTIREV_MODEL_URL", "http://127.0.0.1:7777/v1")
MODEL_API_KEY = os.environ.get("ANTIREV_MODEL_KEY", "sk-local")
MODEL_NAME = os.environ.get("ANTIREV_MODEL_NAME", "qwen3.6-35b-a3b-6bit")

# —— IDA ——
IDA_APP = Path(os.environ.get(
    "ANTIREV_IDA_APP", "/Applications/IDA Professional 9.3.app"))
# IDA worker 用的 Python 3.14 解释器(idalib 已激活的 venv)
IDA_PY314 = Path(os.environ.get(
    "ANTIREV_IDA_PY314", str(Path.home() / ".antirev/ida314-venv/bin/python")))

# —— 超时预算(秒) ——
IDA_ANALYSIS_TIMEOUT = int(os.environ.get("ANTIREV_IDA_TIMEOUT", "180"))
IDA_QUERY_TIMEOUT = int(os.environ.get("ANTIREV_IDA_QUERY_TIMEOUT", "30"))
ANGR_TIMEOUT = int(os.environ.get("ANTIREV_ANGR_TIMEOUT", "120"))
ANGR_MAX_STATES = int(os.environ.get("ANTIREV_ANGR_MAX_STATES", "200"))
TERMINAL_TIMEOUT = int(os.environ.get("ANTIREV_TERMINAL_TIMEOUT", "30"))
PER_CHALLENGE_BUDGET = int(os.environ.get("ANTIREV_CHALL_BUDGET", "1200"))  # 20min

# —— 日志 ——
LOG_DIR = Path(os.environ.get("ANTIREV_LOG_DIR", str(PROJECT_ROOT / "logs")))

# —— 求解成功/失败关键词(§5.2 solve.locate_targets 用) ——
# 注:刻意剔除过泛的词(flag/error/bad),它们会误匹配 "input flag:"、CRT "Unknown error" 等。
SUCCESS_KEYWORDS = [
    "correct", "congrat", "right", "well done", "good job", "you win",
    "you got", "accepted", "success", "solved", "great job", "nice job",
    "get flag", "get the flag",   # 2000 funnyre 正解输出 "you get flag!"(原 "you got" 匹配不上)
]
FAIL_KEYWORDS = [
    "wrong", "incorrect", "invalid", "denied", "try again", "nope",
    "failed", "not right", "not correct",
]
