#!/usr/bin/env python3
"""Run runtime-v2 workers locally while operating on a remote queue over SSH."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import signal
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from route_hacker.runtime_v2.auditor import TraeXRuntimeAuditor
from route_hacker.runtime_v2.models import FailureReason, RuntimeTask
from route_hacker.runtime_v2.verifier import VerificationResult


REMOTE_CACHE_DIRECTORIES = {
    "tmp": "tmp",
    "xdg": "xdg-cache",
    "maven": "m2-repository",
    "gradle": "gradle",
    "npm": "npm",
    "yarn": "yarn",
    "pip": "pip",
    "go_build": "go-build",
    "go_mod": "go-mod",
    "composer": "composer",
    "docker_tmp": "docker-tmp",
}


def remote_environment_prefix(runtime_root: str) -> str:
    root = runtime_root.rstrip("/")
    paths = {
        name: f"{root}/{suffix}"
        for name, suffix in REMOTE_CACHE_DIRECTORIES.items()
    }
    mkdir = "mkdir -p " + " ".join(shlex.quote(path) for path in paths.values())
    environment = {
        "TMPDIR": paths["tmp"],
        "TMP": paths["tmp"],
        "TEMP": paths["tmp"],
        "XDG_CACHE_HOME": paths["xdg"],
        "MAVEN_OPTS": f"-Dmaven.repo.local={paths['maven']}",
        "GRADLE_USER_HOME": paths["gradle"],
        "NPM_CONFIG_CACHE": paths["npm"],
        "YARN_CACHE_FOLDER": paths["yarn"],
        "PIP_CACHE_DIR": paths["pip"],
        "GOCACHE": paths["go_build"],
        "GOMODCACHE": paths["go_mod"],
        "COMPOSER_CACHE_DIR": paths["composer"],
        "DOCKER_TMPDIR": paths["docker_tmp"],
    }
    exports = " ".join(
        f"{name}={shlex.quote(value)}" for name, value in environment.items()
    )
    return f"{mkdir} && export {exports}"


@dataclass(frozen=True)
class LocalAgentRun:
    command: list[str]
    returncode: int | None
    timed_out: bool
    elapsed_seconds: float
    stdout_path: str
    stderr_path: str
    final_message_path: str
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_command(
    command: Sequence[str],
    *,
    input_text: str | None = None,
    timeout: int | None = None,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(part) for part in command],
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        cwd=cwd,
        check=False,
    )


class RemoteRuntime:
    def __init__(
        self,
        *,
        host: str,
        remote_repo: str,
        run_dir: str,
        runtime_root: str,
    ):
        self.host = host
        self.remote_repo = remote_repo.rstrip("/")
        self.run_dir = run_dir
        self.runtime_root = runtime_root.rstrip("/")
        self.environment_prefix = remote_environment_prefix(self.runtime_root)

    def step(self, payload: dict[str, Any], *, timeout: int = 60) -> Any:
        command = [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=20",
            self.host,
            (
                f"{self.environment_prefix} && "
                f"export PYTHONPATH={shlex.quote(self.remote_repo + '/src')} && "
                f"python3 {shlex.quote(self.remote_repo + '/scripts/runtime_v2_remote_step.py')}"
            ),
        ]
        value = dict(payload)
        value["run_dir"] = self.run_dir
        encoded = json.dumps(value, ensure_ascii=False)
        completed: subprocess.CompletedProcess[str] | None = None
        for attempt in range(4):
            completed = run_command(command, input_text=encoded, timeout=timeout)
            if completed.returncode == 0:
                break
            stderr = completed.stderr or completed.stdout
            if completed.returncode != 255 and "Network is unreachable" not in stderr:
                break
            if attempt < 3:
                time.sleep(5 * (attempt + 1))
        assert completed is not None
        if completed.returncode != 0:
            raise RuntimeError(
                f"remote step {payload.get('action')} failed with {completed.returncode}: "
                f"{completed.stderr[-4000:] or completed.stdout[-4000:]}"
            )
        return json.loads(completed.stdout)


class LocalTraeXAgent:
    def __init__(
        self,
        *,
        command: Sequence[str],
        log_root: Path,
        remote_host: str,
        remote_repo: str,
        remote_run_dir: str,
        remote_runtime_root: str,
        remote_proxy: str | None = None,
    ):
        self.command = [str(part) for part in command]
        self.log_root = log_root
        self.remote_host = remote_host
        self.remote_repo = remote_repo.rstrip("/")
        self.remote_run_dir = remote_run_dir
        self.remote_runtime_root = remote_runtime_root.rstrip("/")
        self.remote_environment_prefix = remote_environment_prefix(
            self.remote_runtime_root
        )
        self.remote_proxy = remote_proxy

    def run(
        self,
        *,
        task_id: str,
        attempt_id: int | None,
        attempt_kind: str,
        attempt_dir: str,
        prompt: str,
        timeout_seconds: int,
    ) -> LocalAgentRun:
        local_dir = Path(
            tempfile.mkdtemp(
                prefix=f"{task_id}-{attempt_kind}-",
                dir=str(self.log_root),
            )
        )
        stdout_path = local_dir / "agent.stdout.jsonl"
        stderr_path = local_dir / "agent.stderr.log"
        final_message_path = local_dir / "agent.final.txt"
        remote_workspace = f"{attempt_dir}/workspace"
        remote_candidate = f"{attempt_dir}/candidate-result.json"
        if attempt_id is not None:
            remote_inner = " ".join(
                [
                    self.remote_environment_prefix,
                    "&&",
                    f"export PYTHONPATH={shlex.quote(self.remote_repo + '/src')}",
                    "&&",
                    "python3",
                    "-m",
                    "route_hacker.runtime_v2",
                    "submit-result",
                    "--run-dir",
                    shlex.quote(self.remote_run_dir),
                    "--task-id",
                    shlex.quote(task_id),
                    "--attempt-id",
                    str(attempt_id),
                    "--candidate",
                    shlex.quote(remote_candidate),
                ]
            )
            remote_submit = " ".join(
                [
                    "ssh",
                    shlex.quote(self.remote_host),
                    shlex.quote(remote_inner),
                ]
            )
            prompt = prompt.replace("__REMOTE_SUBMIT_COMMAND__", remote_submit)
        wrapped_prompt = "\n".join(
            [
                "You are the local Agent for a remote runtime-v2 build attempt.",
                f"Remote host: {self.remote_host}",
                f"Remote attempt directory: {attempt_dir}",
                f"Remote workspace: {remote_workspace}",
                f"Remote candidate result: {remote_candidate}",
                (
                    f"Remote proxy hint: {self.remote_proxy}"
                    if self.remote_proxy
                    else "Remote proxy hint: none supplied"
                ),
                "Remote writable shared cache root: "
                "/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/shared-cache",
                f"Remote run-specific runtime root: {self.remote_runtime_root}",
                "Prefix every remote shell command with this exact environment setup:",
                self.remote_environment_prefix + " &&",
                "",
                "Run filesystem, Docker, build, and service commands on the remote host with ssh.",
                "Do not build in the local temporary directory.",
                "You may clone source, install dependencies, edit remote files, pull helper images,",
                "start services, and repair build failures on the remote host.",
                "Do not run destructive shared-host cleanup commands such as docker system prune,",
                "docker builder prune, docker image prune, docker container prune, or Docker daemon restarts.",
                "Only remove containers, images, volumes, or temporary files that you created for this attempt.",
                "If a remote proxy hint is supplied, use it for git, curl, Maven, Gradle, npm,",
                "pip, Docker build args, and other outbound fetches when useful.",
                "Use writable caches under the shared cache root when default home caches fail.",
                "In particular, /data/lhq/.m2 is not writable; run Maven with",
                "-Dmaven.repo.local=/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/shared-cache/m2-repository",
                "or set an equivalent local repository path inside the attempt workspace.",
                "Keep GRADLE_USER_HOME, npm/yarn/pip/Go/Composer caches, TMPDIR, and",
                "Docker client temporary files under the supplied run-specific runtime root.",
                "On this host, GitHub smart-git over HTTPS may fail with TLS errors;",
                "prefer codeload.github.com tarball/zip downloads through the proxy when",
                "clone/fetch is unreliable, then unpack and continue from that source tree.",
                "Use the submission command from the original prompt. Keep secrets out of files.",
                "",
                "Original runtime-v2 prompt:",
                prompt,
            ]
        )
        command = [
            *self.command,
            "--json",
            "--ephemeral",
            "-y",
            "--skip-git-repo-check",
            "--output-last-message",
            str(final_message_path),
            "-",
        ]
        started = time.monotonic()
        returncode: int | None = None
        timed_out = False
        error = None
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            process = subprocess.Popen(
                command,
                cwd=local_dir,
                stdin=subprocess.PIPE,
                stdout=stdout,
                stderr=stderr,
                text=True,
                start_new_session=True,
            )
            try:
                process.communicate(input=wrapped_prompt, timeout=timeout_seconds)
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                error = f"agent timed out after {timeout_seconds} seconds"
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                returncode = 124
        return LocalAgentRun(
            command=command,
            returncode=returncode,
            timed_out=timed_out,
            elapsed_seconds=round(time.monotonic() - started, 3),
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            final_message_path=str(final_message_path),
            error=error,
        )


class Worker:
    def __init__(
        self,
        *,
        remote: RemoteRuntime,
        agent: LocalTraeXAgent,
        owner: str,
        lease_seconds: int,
        attempt_timeout_seconds: int,
        diagnosis_timeout_seconds: int,
        poll_seconds: float,
        stop_when_empty: bool,
        max_idle_rounds: int | None,
        max_tasks: int | None,
        auditor: TraeXRuntimeAuditor,
        audit_log_root: Path,
    ):
        self.remote = remote
        self.agent = agent
        self.owner = owner
        self.lease_seconds = lease_seconds
        self.attempt_timeout_seconds = attempt_timeout_seconds
        self.diagnosis_timeout_seconds = diagnosis_timeout_seconds
        self.poll_seconds = poll_seconds
        self.stop_when_empty = stop_when_empty
        self.max_idle_rounds = max_idle_rounds
        self.max_tasks = max_tasks
        self.auditor = auditor
        self.audit_log_root = audit_log_root

    def run(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        idle = 0
        while self.max_idle_rounds is None or idle < self.max_idle_rounds:
            if self.max_tasks is not None and len(results) >= self.max_tasks:
                break
            claimed = self.remote.step(
                {
                    "action": "claim",
                    "owner": self.owner,
                    "lease_seconds": self.lease_seconds,
                }
            )
            if claimed is None:
                pending = self.remote.step({"action": "has_pending"}).get(
                    "has_pending"
                )
                if self.stop_when_empty and not pending:
                    break
                idle = idle + 1 if self.max_idle_rounds is not None else 0
                time.sleep(self.poll_seconds)
                continue
            idle = 0
            results.append(self.run_task(claimed))
        return results

    def run_task(self, task: dict[str, Any]) -> dict[str, Any]:
        heartbeat_stop = threading.Event()
        heartbeat = threading.Thread(
            target=self._heartbeat,
            args=(task["task_id"], heartbeat_stop),
            daemon=True,
        )
        heartbeat.start()
        try:
            while True:
                prepared_result = self.remote.step(
                    {"action": "prepare_attempt", "task": task},
                    timeout=120,
                )
                if "done" in prepared_result:
                    return prepared_result["done"]
                prepared = prepared_result["prepared"]
                timeout = (
                    self.diagnosis_timeout_seconds
                    if prepared["attempt_kind"] == "diagnosis"
                    else self.attempt_timeout_seconds
                )
                agent_run = self.agent.run(
                    task_id=task["task_id"],
                    attempt_id=prepared["attempt_id"],
                    attempt_kind=prepared["attempt_kind"],
                    attempt_dir=prepared["attempt_dir"],
                    prompt=prepared["prompt"],
                    timeout_seconds=timeout,
                )
                audit = None
                if prepared["attempt_kind"] != "diagnosis":
                    verification = self.remote.step(
                        {
                            "action": "verify_attempt",
                            "task": task,
                            "attempt_dir": prepared["attempt_dir"],
                            "attempt_id": prepared["attempt_id"],
                        },
                        timeout=600,
                    )
                    mechanical = verification.get("verification")
                    if mechanical and mechanical.get("status") == "passed":
                        audit_dir = (
                            self.audit_log_root
                            / task["task_id"]
                            / f"{prepared['attempt_index']:02d}-{prepared['attempt_kind']}"
                        )
                        audit_result = self.auditor.audit_evidence(
                            task=RuntimeTask(
                                task_id=task["task_id"],
                                prompt=task["prompt"],
                                project_key=task.get("project_key"),
                                priority=int(task.get("priority", 0)),
                                status=task.get("status", "running"),
                                attempt_index=int(task.get("attempt_index", 0)),
                            ),
                            attempt_dir=Path(prepared["attempt_dir"]),
                            result_path=Path(str(verification["result_path"])),
                            verification=verification_from_mapping(mechanical),
                            artifact_dir=audit_dir,
                            execution_cwd=audit_dir,
                            remote_host=self.remote.host,
                        )
                        audit = audit_result.to_dict()
                finished = self.remote.step(
                    {
                        "action": "finish_attempt",
                        "task": task,
                        "attempt_dir": prepared["attempt_dir"],
                        "attempt_id": prepared["attempt_id"],
                        "attempt_index": prepared["attempt_index"],
                        "attempt_kind": prepared["attempt_kind"],
                        "prior_attempts": prepared.get("prior_attempts") or [],
                        "agent_run": agent_run.to_dict(),
                        "audit": audit,
                    },
                    timeout=600,
                )
                if "final" in finished:
                    return finished["final"]
        finally:
            heartbeat_stop.set()
            heartbeat.join(timeout=1)

    def _heartbeat(self, task_id: str, stop: threading.Event) -> None:
        interval = max(5.0, min(60.0, self.lease_seconds / 3))
        while not stop.wait(interval):
            try:
                result = self.remote.step(
                    {
                        "action": "heartbeat",
                        "task_id": task_id,
                        "owner": self.owner,
                        "lease_seconds": self.lease_seconds,
                    },
                    timeout=60,
                )
            except Exception:
                return
            if not result.get("ok"):
                return


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run runtime-v2 queue workers locally against a remote SSH host."
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--remote-repo", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--lease-seconds", type=int, default=25200)
    parser.add_argument("--attempt-timeout-seconds", type=int, default=7200)
    parser.add_argument("--diagnosis-timeout-seconds", type=int, default=1800)
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    parser.add_argument("--stop-when-empty", action="store_true")
    parser.add_argument("--max-idle-rounds", type=int)
    parser.add_argument(
        "--idle-rounds",
        type=int,
        help="Deprecated alias for --max-idle-rounds.",
    )
    parser.add_argument("--agent-command", default="traex exec")
    parser.add_argument("--audit-command", default="traex")
    parser.add_argument("--audit-timeout-seconds", type=int, default=900)
    parser.add_argument("--remote-proxy")
    parser.add_argument(
        "--remote-runtime-root",
        help="Remote /mnt-backed root for temporary files and build caches.",
    )
    parser.add_argument(
        "--owner-prefix",
        help="Unique lease-owner prefix for this worker process group.",
    )
    parser.add_argument(
        "--max-tasks",
        type=int,
        help="Maximum tasks for each local worker process to claim before exiting.",
    )
    parser.add_argument("--log-root", type=Path, default=Path("/tmp/runtime-v2-local-agent"))
    return parser


def verification_from_mapping(value: dict[str, Any]) -> VerificationResult:
    reason_value = value.get("reason")
    reason = (
        FailureReason(
            stage=str(reason_value["stage"]),
            code=str(reason_value["code"]),
            message=str(reason_value["message"]),
            evidence_path=(
                str(reason_value["evidence_path"])
                if reason_value.get("evidence_path") is not None
                else None
            ),
        )
        if isinstance(reason_value, dict)
        else None
    )
    return VerificationResult(
        status=str(value["status"]),
        launch_type=value.get("launch_type"),
        primary_image=value.get("primary_image"),
        started=bool(value.get("started")),
        probe_results=list(value.get("probe_results") or []),
        launch_info=dict(value.get("launch_info") or {}),
        error=value.get("error"),
        reason=reason,
    )


def main() -> int:
    args = build_parser().parse_args()
    args.log_root.mkdir(parents=True, exist_ok=True)
    remote_runtime_root = (
        args.remote_runtime_root
        or f"{args.run_dir.rstrip('/')}/host-runtime"
    )
    remote = RemoteRuntime(
        host=args.host,
        remote_repo=args.remote_repo,
        run_dir=args.run_dir,
        runtime_root=remote_runtime_root,
    )
    agent = LocalTraeXAgent(
        command=shlex.split(args.agent_command),
        log_root=args.log_root,
        remote_host=args.host,
        remote_repo=args.remote_repo,
        remote_run_dir=args.run_dir,
        remote_runtime_root=remote_runtime_root,
        remote_proxy=args.remote_proxy,
    )
    auditor = TraeXRuntimeAuditor(
        command=shlex.split(args.audit_command),
        timeout_seconds=args.audit_timeout_seconds,
    )
    owner_prefix = args.owner_prefix
    if not owner_prefix:
        owner_seed = f"{os.uname().nodename}:{os.getpid()}:{args.log_root.resolve()}"
        owner_suffix = hashlib.sha1(owner_seed.encode("utf-8")).hexdigest()[:10]
        owner_prefix = f"runtime-v2-local-ssh-worker-{owner_suffix}"
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(
                Worker(
                    remote=remote,
                    agent=agent,
                    owner=f"{owner_prefix}-{index + 1}",
                    lease_seconds=args.lease_seconds,
                    attempt_timeout_seconds=args.attempt_timeout_seconds,
                    diagnosis_timeout_seconds=args.diagnosis_timeout_seconds,
                    poll_seconds=args.poll_seconds,
                    stop_when_empty=args.stop_when_empty,
                    max_idle_rounds=(
                        args.max_idle_rounds
                        if args.max_idle_rounds is not None
                        else args.idle_rounds
                    ),
                    max_tasks=args.max_tasks,
                    auditor=auditor,
                    audit_log_root=args.log_root / "audits",
                ).run
            )
            for index in range(args.workers)
        ]
        results = []
        for future in as_completed(futures):
            results.extend(future.result())
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
