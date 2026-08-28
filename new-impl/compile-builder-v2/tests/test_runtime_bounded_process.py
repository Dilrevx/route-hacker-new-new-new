from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from gca.runtime.bounded_process import run_bounded_process


def _assert_process_exited(pid: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    os.kill(pid, 9)
    raise AssertionError(f"process {pid} survived bounded-process cleanup")


def test_bounded_process_returns_normal_exit() -> None:
    result = run_bounded_process(
        [sys.executable, "-c", "print('ok')"],
        timeout_seconds=5,
    )

    assert result.returncode == 0
    assert result.timed_out is False
    assert result.cleanup_attempted is False
    assert result.to_dict()["command"][-1] == "print('ok')"


def test_bounded_process_writes_input_through_anonymous_pipe(tmp_path: Path) -> None:
    output_path = tmp_path / "stdout.txt"
    with output_path.open("w", encoding="utf-8") as handle:
        result = run_bounded_process(
            [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
            timeout_seconds=5,
            input_data="proposal packet",
            stdout=handle,
            text=True,
        )

    assert result.returncode == 0
    assert output_path.read_text(encoding="utf-8") == "PROPOSAL PACKET\n"


def test_bounded_process_rejects_file_stdin_and_input_data_together() -> None:
    with pytest.raises(ValueError, match="cannot both be set"):
        run_bounded_process(
            [sys.executable, "-c", "pass"],
            timeout_seconds=5,
            stdin=subprocess.DEVNULL,
            input_data="proposal packet",
            text=True,
        )


def test_bounded_process_cleans_child_new_session_on_timeout(tmp_path: Path) -> None:
    child_pid_path = tmp_path / "child.pid"
    command = [
        sys.executable,
        "-c",
        (
            "import pathlib, subprocess, sys, time; "
            "child=subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
            "start_new_session=True); "
            f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid)); "
            "time.sleep(30)"
        ),
    ]

    result = run_bounded_process(
        command,
        timeout_seconds=0.2,
        term_grace_seconds=0.2,
    )

    assert result.returncode == 124
    assert result.timed_out is True
    assert result.cleanup_attempted is True
    assert result.cleanup_process_groups
    _assert_process_exited(int(child_pid_path.read_text(encoding="utf-8")))
