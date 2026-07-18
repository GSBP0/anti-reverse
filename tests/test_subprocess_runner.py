import sys

from antirev.isolation.subprocess_runner import run_isolated, IsolatedResult


def test_captures_stdout_and_rc():
    r = run_isolated([sys.executable, "-c", "print('hi')"], timeout=10)
    assert isinstance(r, IsolatedResult)
    assert r.returncode == 0
    assert "hi" in r.stdout
    assert r.timed_out is False


def test_timeout_is_flagged_not_raised():
    r = run_isolated([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert r.timed_out is True
    assert r.returncode != 0


def test_crash_is_captured_not_propagated():
    r = run_isolated([sys.executable, "-c", "import os; os._exit(3)"], timeout=10)
    assert r.returncode == 3
    assert r.timed_out is False


def test_missing_binary_is_structured_error():
    r = run_isolated(["/nonexistent/binary_xyz"], timeout=5)
    assert r.returncode == 127
    assert "spawn failed" in r.stderr


def test_stdin_is_piped():
    r = run_isolated([sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"],
                     timeout=10, input_text="echoed")
    assert "echoed" in r.stdout
