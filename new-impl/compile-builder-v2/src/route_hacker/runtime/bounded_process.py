"""Bounded subprocess execution with process-tree-aware timeout cleanup.

Long-running build and evaluator tools sometimes create their own process
groups.  Killing only the top-level worker then leaves those descendants alive.
This module starts each invocation in a dedicated session and, on timeout,
terminates every descendant process group observed from the worker's process
tree.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class BoundedProcessResult:
    """Terminal result and cleanup evidence for a bounded invocation."""

    command: list[str]
    pid: int
    returncode: int | None
    timed_out: bool
    inactivity_timed_out: bool
    elapsed_seconds: float
    process_group: int | None
    cleanup_attempted: bool
    cleanup_process_groups: list[int]
    cleanup_signal: str | None
    cleanup_result: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _descendant_pids(root_pid: int) -> set[int]:
    """Return the worker and currently observable descendants from ``ps``."""

    result = subprocess.run(
        ["ps", "-eo", "pid=,ppid="],
        check=False,
        capture_output=True,
        text=True,
    )
    children_by_parent: dict[int, list[int]] = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            pid, parent_pid = (int(part) for part in parts)
        except ValueError:
            continue
        children_by_parent.setdefault(parent_pid, []).append(pid)

    descendants: set[int] = set()
    pending = [root_pid]
    while pending:
        pid = pending.pop()
        if pid in descendants:
            continue
        descendants.add(pid)
        pending.extend(children_by_parent.get(pid, []))
    return descendants


def _process_groups(root_pid: int) -> list[int]:
    groups: set[int] = set()
    for pid in _descendant_pids(root_pid):
        try:
            groups.add(os.getpgid(pid))
        except ProcessLookupError:
            continue
    return sorted(groups, reverse=True)


def _signal_groups(process_groups: Iterable[int], sig: signal.Signals) -> None:
    for process_group in process_groups:
        try:
            os.killpg(process_group, sig)
        except (ProcessLookupError, PermissionError):
            continue


def _cleanup_timed_out_process(
    proc: subprocess.Popen[Any],
    *,
    term_grace_seconds: float,
) -> tuple[int | None, list[int], str, str]:
    process_groups = _process_groups(proc.pid)
    root_group = _safe_process_group(proc.pid)
    if root_group is not None:
        process_groups = sorted({*process_groups, root_group}, reverse=True)

    _signal_groups(process_groups, signal.SIGTERM)
    cleanup_signal = "SIGTERM"
    cleanup_result = "terminated_after_sigterm"
    try:
        proc.wait(timeout=term_grace_seconds)
    except subprocess.TimeoutExpired:
        # Re-scan before escalation: descendants can fork their own
        # process group after the first tree snapshot.
        escalation_groups = set(process_groups)
        escalation_groups.update(_process_groups(proc.pid))
        _signal_groups(sorted(escalation_groups, reverse=True), signal.SIGKILL)
        cleanup_signal = "SIGKILL"
        cleanup_result = "killed_after_sigterm_timeout"
        proc.wait()
    return root_group, process_groups, cleanup_signal, cleanup_result


def run_bounded_process(
    command: Sequence[str],
    *,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float,
    term_grace_seconds: float = 10.0,
    inactivity_timeout_seconds: float | None = None,
    progress_path: Path | str | None = None,
    poll_interval_seconds: float = 1.0,
    stdin: Any = None,
    input_data: str | bytes | None = None,
    stdout: Any = None,
    stderr: Any = None,
    text: bool | None = None,
) -> BoundedProcessResult:
    """Run a command with bounded lifetime and descendant-group cleanup.

    The caller owns output files.  This function records process-group cleanup
    evidence but never interprets the command's semantic result.
    """

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if term_grace_seconds < 0:
        raise ValueError("term_grace_seconds must be non-negative")
    if inactivity_timeout_seconds is not None and inactivity_timeout_seconds <= 0:
        raise ValueError("inactivity_timeout_seconds must be positive when set")
    if poll_interval_seconds <= 0:
        raise ValueError("poll_interval_seconds must be positive")
    if inactivity_timeout_seconds is not None and progress_path is None:
        raise ValueError("progress_path is required with inactivity_timeout_seconds")
    if stdin is not None and input_data is not None:
        raise ValueError("stdin and input_data cannot both be set")

    argv = [str(part) for part in command]
    if not argv:
        raise ValueError("command must not be empty")

    started = time.monotonic()
    process_stdin = subprocess.PIPE if input_data is not None else stdin
    proc = subprocess.Popen(
        argv,
        cwd=str(cwd) if cwd is not None else None,
        env=dict(env) if env is not None else None,
        stdin=process_stdin,
        stdout=stdout,
        stderr=stderr,
        text=text,
        start_new_session=True,
    )
    observed_progress = _progress_signature(progress_path)
    last_progress_at = time.monotonic()
    try:
        if input_data is not None:
            proc.stdin.write(input_data)
            proc.stdin.close()
        while True:
            returncode = proc.poll()
            if returncode is not None:
                break
            elapsed_seconds = time.monotonic() - started
            if elapsed_seconds >= timeout_seconds:
                raise subprocess.TimeoutExpired(argv, timeout_seconds)
            if inactivity_timeout_seconds is not None:
                current_progress = _progress_signature(progress_path)
                if current_progress != observed_progress:
                    observed_progress = current_progress
                    last_progress_at = time.monotonic()
                elif time.monotonic() - last_progress_at >= inactivity_timeout_seconds:
                    root_group, process_groups, cleanup_signal, cleanup_result = (
                        _cleanup_timed_out_process(
                            proc,
                            term_grace_seconds=term_grace_seconds,
                        )
                    )
                    return BoundedProcessResult(
                        command=argv,
                        pid=proc.pid,
                        returncode=124,
                        timed_out=True,
                        inactivity_timed_out=True,
                        elapsed_seconds=round(time.monotonic() - started, 3),
                        process_group=root_group,
                        cleanup_attempted=True,
                        cleanup_process_groups=process_groups,
                        cleanup_signal=cleanup_signal,
                        cleanup_result=cleanup_result,
                    )
            time.sleep(min(poll_interval_seconds, max(0.01, timeout_seconds - elapsed_seconds)))
        return BoundedProcessResult(
            command=argv,
            pid=proc.pid,
            returncode=returncode,
            timed_out=False,
            inactivity_timed_out=False,
            elapsed_seconds=round(time.monotonic() - started, 3),
            process_group=_safe_process_group(proc.pid),
            cleanup_attempted=False,
            cleanup_process_groups=[],
            cleanup_signal=None,
            cleanup_result=None,
        )
    except subprocess.TimeoutExpired:
        root_group, process_groups, cleanup_signal, cleanup_result = (
            _cleanup_timed_out_process(
                proc,
                term_grace_seconds=term_grace_seconds,
            )
        )

        return BoundedProcessResult(
            command=argv,
            pid=proc.pid,
            returncode=124,
            timed_out=True,
            inactivity_timed_out=False,
            elapsed_seconds=round(time.monotonic() - started, 3),
            process_group=root_group,
            cleanup_attempted=True,
            cleanup_process_groups=process_groups,
            cleanup_signal=cleanup_signal,
            cleanup_result=cleanup_result,
        )


def _safe_process_group(pid: int) -> int | None:
    try:
        return os.getpgid(pid)
    except ProcessLookupError:
        return None


def _progress_signature(path: Path | str | None) -> tuple[int, int] | None:
    if path is None:
        return None
    try:
        stat = Path(path).stat()
    except FileNotFoundError:
        return None
    return stat.st_mtime_ns, stat.st_size
