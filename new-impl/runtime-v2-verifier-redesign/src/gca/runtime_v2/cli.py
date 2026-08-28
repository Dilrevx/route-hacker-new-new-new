"""Command-line interface for the autonomous runtime-v2 queue."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
from pathlib import Path
from typing import Sequence

from .agent import LocalAgentBackend
from .auditor import LocalRuntimeAuditor
from .orchestrator import OrchestratorConfig, RuntimeV2Orchestrator
from .queue import QueueStore
from .scheduler import RuntimeScheduler
from .submission import ResultSubmissionService
from .verifier import RuntimeVerifier
from .workspace import WorkspaceManager


def _queue(run_dir: Path) -> QueueStore:
    return QueueStore(run_dir.resolve() / "queue.db")


def _default_agent_command() -> str:
    configured = os.environ.get("RUNTIME_V2_AGENT_COMMAND")
    if configured:
        return configured
    for command in ("codex",):
        if shutil.which(command):
            return command
    return "codex"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Autonomous agent runtime environment builder v2."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init")
    init.add_argument("--run-dir", type=Path, required=True)

    submit = subparsers.add_parser("submit")
    submit.add_argument("--run-dir", type=Path, required=True)
    submit.add_argument("--task-id", required=True)
    submit.add_argument("--task-file", type=Path, required=True)
    submit.add_argument("--project-key")
    submit.add_argument("--priority", type=int, default=0)

    submit_jsonl = subparsers.add_parser("submit-jsonl")
    submit_jsonl.add_argument("--run-dir", type=Path, required=True)
    submit_jsonl.add_argument("--input", type=Path, required=True)

    submit_result = subparsers.add_parser("submit-result")
    submit_result.add_argument("--run-dir", type=Path, required=True)
    submit_result.add_argument("--task-id", required=True)
    submit_result.add_argument("--attempt-id", type=int, required=True)
    submit_result.add_argument("--candidate", type=Path, required=True)

    run = subparsers.add_parser("run")
    run.add_argument("--run-dir", type=Path, required=True)
    run.add_argument("--workers", type=int, default=4)
    run.add_argument("--attempt-timeout-seconds", type=int, default=7200)
    run.add_argument("--diagnosis-timeout-seconds", type=int, default=1800)
    run.add_argument("--lease-seconds", type=int)
    run.add_argument("--poll-seconds", type=float, default=2.0)
    run.add_argument("--idle-rounds", type=int, default=3)
    run.add_argument(
        "--agent-command",
        default=_default_agent_command(),
    )
    run.add_argument("--agent-arg", action="append", default=[])
    run.add_argument("--audit-command", default=_default_agent_command())
    run.add_argument("--audit-arg", action="append", default=[])
    run.add_argument("--audit-timeout-seconds", type=int, default=900)

    status = subparsers.add_parser("status")
    status.add_argument("--run-dir", type=Path, required=True)

    cancel = subparsers.add_parser("cancel")
    cancel.add_argument("--run-dir", type=Path, required=True)
    cancel.add_argument("--task-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    run_dir = args.run_dir.resolve()
    if args.command == "init":
        run_dir.mkdir(parents=True, exist_ok=True)
        _queue(run_dir)
        print(json.dumps({"status": "initialized", "run_dir": str(run_dir)}))
        return 0
    queue = _queue(run_dir)
    if args.command == "submit":
        task = queue.submit(
            task_id=args.task_id,
            prompt=args.task_file.read_text(encoding="utf-8"),
            project_key=args.project_key,
            priority=args.priority,
        )
        print(json.dumps(task.__dict__, ensure_ascii=False, sort_keys=True))
        return 0
    if args.command == "submit-jsonl":
        submitted = []
        for line in args.input.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            task = queue.submit(
                task_id=value["task_id"],
                prompt=value["prompt"],
                project_key=value.get("project_key"),
                priority=value.get("priority", 0),
            )
            submitted.append(task.task_id)
        print(json.dumps({"submitted": submitted}, ensure_ascii=False))
        return 0
    if args.command == "submit-result":
        result = ResultSubmissionService(queue).submit(
            task_id=args.task_id,
            attempt_id=args.attempt_id,
            candidate_path=args.candidate,
        )
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        return 0 if result.accepted else 2
    if args.command == "status":
        print(json.dumps(queue.list_tasks(), ensure_ascii=False, indent=2))
        return 0
    if args.command == "cancel":
        cancelled = queue.cancel(args.task_id)
        print(json.dumps({"task_id": args.task_id, "cancel_requested": cancelled}))
        return 0 if cancelled else 1

    attempt_timeout = args.attempt_timeout_seconds
    diagnosis_timeout = args.diagnosis_timeout_seconds
    lease_seconds = args.lease_seconds or (
        attempt_timeout * 3 + diagnosis_timeout + 600
    )
    agent = LocalAgentBackend(
        command=shlex.split(args.agent_command),
        extra_args=args.agent_arg,
    )
    workspaces = WorkspaceManager(run_dir)
    orchestrator = RuntimeV2Orchestrator(
        queue=queue,
        workspaces=workspaces,
        agent=agent,
        verifier=RuntimeVerifier(),
        auditor=LocalRuntimeAuditor(
            command=shlex.split(args.audit_command),
            extra_args=args.audit_arg,
            timeout_seconds=args.audit_timeout_seconds,
        ),
        config=OrchestratorConfig(
            attempt_timeout_seconds=attempt_timeout,
            diagnosis_timeout_seconds=diagnosis_timeout,
        ),
    )
    scheduler = RuntimeScheduler(
        queue=queue,
        orchestrator=orchestrator,
        workers=args.workers,
        lease_seconds=lease_seconds,
        poll_seconds=args.poll_seconds,
        idle_rounds=args.idle_rounds,
    )
    results = scheduler.run_until_idle()
    print(json.dumps(results, ensure_ascii=False, indent=2))
    return 0
