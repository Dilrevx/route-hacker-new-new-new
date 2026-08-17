#!/usr/bin/env python3
"""Keep orphaned local agent attempts alive and finalize their result.json files.

This is a recovery helper for runtime-v2 runs where the local Python worker died
but its `traex exec` child process kept running and may still write result.json.
It does not build anything and does not add verification rules; it only sends
heartbeats and calls the existing remote finish_attempt action.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any, Sequence


def run_command(
    command: Sequence[str],
    *,
    input_text: str | None = None,
    timeout: int | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(part) for part in command],
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


class RemoteRuntime:
    def __init__(self, *, host: str, remote_repo: str, run_dir: str):
        self.host = host
        self.remote_repo = remote_repo.rstrip("/")
        self.run_dir = run_dir

    def step(self, payload: dict[str, Any], *, timeout: int = 120) -> Any:
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=20",
            self.host,
            (
                f"PYTHONPATH={shlex.quote(self.remote_repo + '/src')} "
                f"python3 {shlex.quote(self.remote_repo + '/scripts/runtime_v2_remote_step.py')}"
            ),
        ]
        value = dict(payload)
        value["run_dir"] = self.run_dir
        completed = run_command(
            command,
            input_text=json.dumps(value, ensure_ascii=False),
            timeout=timeout,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"remote step {payload.get('action')} failed with {completed.returncode}: "
                f"{completed.stderr[-4000:] or completed.stdout[-4000:]}"
            )
        return json.loads(completed.stdout)

    def task(self, task_id: str) -> dict[str, Any]:
        script = (
            "import json, sqlite3; "
            f"run={self.run_dir!r}; task_id={task_id!r}; "
            "con=sqlite3.connect(f'file:{run}/queue.db?mode=ro', uri=True, timeout=30); "
            "row=con.execute('select task_id,prompt,project_key,priority,status,attempt_index "
            "from tasks where task_id=?', (task_id,)).fetchone(); "
            "print(json.dumps(dict(zip(['task_id','prompt','project_key','priority','status','attempt_index'], row))))"
        )
        completed = run_command(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=20",
                self.host,
                f"python3 -c {shlex.quote(script)}",
            ],
            timeout=120,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr[-4000:] or completed.stdout[-4000:])
        return json.loads(completed.stdout)

    def attempt_status(self, attempt_id: int) -> str | None:
        script = (
            "import sqlite3; "
            f"run={self.run_dir!r}; attempt_id={int(attempt_id)!r}; "
            "con=sqlite3.connect(f'file:{run}/queue.db?mode=ro', uri=True, timeout=30); "
            "row=con.execute('select status from attempts where id=?', "
            "(attempt_id,)).fetchone(); "
            "print(row[0] if row else '')"
        )
        completed = run_command(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=20",
                self.host,
                f"python3 -c {shlex.quote(script)}",
            ],
            timeout=120,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr[-4000:] or completed.stdout[-4000:])
        status = completed.stdout.strip()
        return status or None

    def release_for_retry(self, task_id: str, *, reason: str) -> None:
        script = (
            "import datetime, sqlite3; "
            f"run={self.run_dir!r}; task_id={task_id!r}; reason={reason!r}; "
            "con=sqlite3.connect(run + '/queue.db', timeout=30); "
            "now=datetime.datetime.now(datetime.UTC).isoformat(); "
            "con.execute(\"update tasks set status='queued', lease_owner=NULL, "
            "lease_expires_at=NULL, updated_at=? where task_id=? and status='running'\", "
            "(now, task_id)); "
            "con.execute(\"insert into events(task_id,event,detail,created_at) "
            "values(?,?,?,?)\", (task_id, 'released_after_orphan_adoption', reason, now)); "
            "con.commit()"
        )
        completed = run_command(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=20",
                self.host,
                f"python3 -c {shlex.quote(script)}",
            ],
            timeout=120,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr[-4000:] or completed.stdout[-4000:])

    def exists(self, path: str) -> bool:
        completed = run_command(["ssh", self.host, "test", "-s", path], timeout=60)
        return completed.returncode == 0


def pid_alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--remote-repo", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--attempts-json", type=Path, required=True)
    parser.add_argument("--owner", default="runtime-v2-local-ssh-worker-1")
    parser.add_argument("--lease-seconds", type=int, default=25200)
    parser.add_argument("--poll-seconds", type=float, default=30.0)
    args = parser.parse_args()

    remote = RemoteRuntime(
        host=args.host,
        remote_repo=args.remote_repo,
        run_dir=args.run_dir,
    )
    attempts = json.loads(args.attempts_json.read_text(encoding="utf-8"))
    remaining = {item["task_id"]: dict(item) for item in attempts}

    while remaining:
        for task_id, item in list(remaining.items()):
            try:
                remote.step(
                    {
                        "action": "heartbeat",
                        "task_id": task_id,
                        "owner": args.owner,
                        "lease_seconds": args.lease_seconds,
                    },
                    timeout=60,
                )
            except Exception as exc:
                print(f"[adopt] heartbeat failed for {task_id}: {exc}", flush=True)

            result_path = f"{item['attempt_dir'].rstrip('/')}/result.json"
            has_result = remote.exists(result_path)
            alive = pid_alive(item.get("pid"))
            if not has_result and alive:
                continue
            if not has_result:
                print(
                    f"[adopt] {task_id} pid exited without result.json; leaving for manual reset",
                    flush=True,
                )
                remaining.pop(task_id, None)
                continue

            task = remote.task(task_id)
            if int(task.get("attempt_index", 0)) > int(item["attempt_index"]):
                print(
                    f"[adopt] {task_id} already advanced to attempt "
                    f"{task.get('attempt_index')}; skipping orphan attempt "
                    f"{item['attempt_index']}",
                    flush=True,
                )
                remaining.pop(task_id, None)
                continue
            attempt_status = remote.attempt_status(int(item["attempt_id"]))
            if attempt_status and attempt_status != "running":
                print(
                    f"[adopt] {task_id} orphan attempt {item['attempt_id']} "
                    f"is already {attempt_status}; skipping",
                    flush=True,
                )
                remaining.pop(task_id, None)
                continue
            agent_run = {
                "command": ["adopt-orphan-traex-exec"],
                "returncode": 0,
                "timed_out": False,
                "elapsed_seconds": 0,
                "stdout_path": item.get("stdout_path", ""),
                "stderr_path": item.get("stderr_path", ""),
                "final_message_path": item.get("final_message_path", ""),
                "error": None,
            }
            payload = {
                "action": "finish_attempt",
                "task": task,
                "attempt_dir": item["attempt_dir"],
                "attempt_id": item["attempt_id"],
                "attempt_index": item["attempt_index"],
                "attempt_kind": item["attempt_kind"],
                "prior_attempts": item.get("prior_attempts", []),
                "agent_run": agent_run,
            }
            finished = remote.step(payload, timeout=600)
            print(json.dumps({task_id: finished}, ensure_ascii=False), flush=True)
            if finished.get("continue"):
                remote.release_for_retry(
                    task_id,
                    reason="orphan result adopted; queued for normal retry",
                )
                print(f"[adopt] {task_id} released for normal retry", flush=True)
            remaining.pop(task_id, None)
        if remaining:
            time.sleep(args.poll_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
