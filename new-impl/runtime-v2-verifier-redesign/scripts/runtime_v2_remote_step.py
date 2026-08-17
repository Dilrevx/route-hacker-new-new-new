#!/usr/bin/env python3
"""Small JSON-RPC helper for local SSH runtime-v2 workers."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from route_hacker.runtime_v2.agent import build_agent_prompt
from route_hacker.runtime_v2.models import FailureReason, RuntimeTask
from route_hacker.runtime_v2.orchestrator import ATTEMPTS
from route_hacker.runtime_v2.queue import QueueStore
from route_hacker.runtime_v2.verifier import RuntimeVerifier
from route_hacker.runtime_v2.workspace import WorkspaceManager


def task_from_dict(value: dict[str, Any]) -> RuntimeTask:
    return RuntimeTask(
        task_id=value["task_id"],
        prompt=value["prompt"],
        project_key=value.get("project_key"),
        priority=int(value.get("priority", 0)),
        status=value.get("status", "queued"),
        attempt_index=int(value.get("attempt_index", 0)),
    )


def write_final(
    *,
    queue: QueueStore,
    workspaces: WorkspaceManager,
    task: RuntimeTask,
    final: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    final_path = workspaces.task_dir(task.task_id) / "final.json"
    workspaces.write_json(final_path, final)
    queue.set_status(
        task_id=task.task_id,
        status=status,
        final_json=final_path,
        release_lease=True,
    )
    return final


def attempt_error(agent_error: str | None, verification: Any) -> str | None:
    if verification is not None and verification.status == "passed":
        return None
    if verification is not None and verification.status != "passed":
        return verification.error or "runtime verification failed"
    if agent_error:
        return agent_error
    return "agent did not produce a verifiable result.json"


def reason_from_mapping(value: Any) -> FailureReason | None:
    if not isinstance(value, dict):
        return None
    try:
        return FailureReason(
            stage=str(value["stage"]),
            code=str(value["code"]),
            message=str(value["message"]),
            evidence_path=(
                str(value["evidence_path"])
                if value.get("evidence_path") is not None
                else None
            ),
        )
    except KeyError:
        return None


def load_attempt_summary(
    *,
    task_dir: Path,
    attempt_index: int,
    attempt_kind: str,
    fallback: dict[str, Any],
) -> dict[str, Any]:
    summary_path = (
        task_dir
        / "attempts"
        / f"{attempt_index:02d}-{attempt_kind}"
        / "attempt_summary.json"
    )
    try:
        value = json.loads(summary_path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            return value
    except Exception:
        pass
    return {
        "attempt_id": fallback["id"],
        "attempt_index": attempt_index,
        "attempt_kind": attempt_kind,
        "status": fallback["status"],
        "error": fallback.get("error"),
    }


def prepare_attempt(
    *,
    queue: QueueStore,
    workspaces: WorkspaceManager,
    task: RuntimeTask,
) -> dict[str, Any]:
    task_dir = workspaces.initialize_task(task)
    attempt_summaries: list[dict[str, Any]] = []
    existing_attempts = {
        int(row["attempt_index"]): row for row in queue.attempts_for(task.task_id)
    }
    for attempt_index, attempt_kind in ATTEMPTS:
        existing = existing_attempts.get(attempt_index)
        if existing and existing["status"] == "failed":
            attempt_summaries.append(
                load_attempt_summary(
                    task_dir=task_dir,
                    attempt_index=attempt_index,
                    attempt_kind=attempt_kind,
                    fallback=existing,
                )
            )
            continue
        if existing and existing["status"] == "passed":
            attempt_summaries.append(
                load_attempt_summary(
                    task_dir=task_dir,
                    attempt_index=attempt_index,
                    attempt_kind=attempt_kind,
                    fallback=existing,
                )
            )
            verification_path = existing.get("verification_path")
            audit_path = existing.get("audit_path")
            result_path = existing.get("result_path")
            if verification_path and audit_path and result_path:
                try:
                    verification = json.loads(Path(str(verification_path)).read_text())
                    audit = json.loads(Path(str(audit_path)).read_text())
                except Exception:
                    verification = {}
                    audit = {}
                if (
                    verification.get("status") == "passed"
                    and audit.get("status") == "passed"
                ):
                    final = {
                        "task_id": task.task_id,
                        "status": "runtime_ready",
                        "successful_attempt": f"{attempt_index:02d}-{attempt_kind}",
                        "primary_image": verification.get("primary_image"),
                        "launch_type": verification.get("launch_type"),
                        "result_path": str(result_path),
                        "verification_path": str(verification_path),
                        "audit_path": str(audit_path),
                        "attempts": attempt_summaries,
                        "resumed_from_completed_attempt": True,
                    }
                    return {
                        "done": write_final(
                            queue=queue,
                            workspaces=workspaces,
                            task=task,
                            final=final,
                            status="runtime_ready",
                        )
                    }
            continue

        attempt_dir = workspaces.prepare_attempt(
            task=task,
            attempt_index=attempt_index,
            kind=attempt_kind,
        )
        for stale_path in (
            attempt_dir / "result.json",
            attempt_dir / "candidate-result.json",
            attempt_dir / "verification.json",
            attempt_dir / "audit.json",
        ):
            stale_path.unlink(missing_ok=True)
        attempt_id = queue.start_attempt(
            task_id=task.task_id,
            attempt_index=attempt_index,
            kind=attempt_kind,
            workspace=attempt_dir,
        )
        previous_dirs = sorted(
            path
            for path in (task_dir / "attempts").glob("[0-9][0-9]-*")
            if int(path.name.split("-", 1)[0]) < attempt_index
        )
        history_paths = []
        if previous_dirs:
            previous = previous_dirs[-1]
            candidates = [
                previous / "agent_run.json",
                previous / "attempt_summary.json",
                previous / "logs" / "agent.stdout.jsonl",
                previous / "logs" / "agent.stderr.log",
                previous / "logs" / "agent.final.txt",
                previous / "verification.json",
                previous / "audit.json",
            ]
            history_paths = [path for path in candidates if path.exists()]
        prompt = build_agent_prompt(
            task=task,
            attempt_kind=attempt_kind,
            attempt_dir=attempt_dir,
            submit_command=["__REMOTE_SUBMIT_COMMAND__"],
            history_paths=history_paths,
        )
        (attempt_dir / "agent_prompt.md").write_text(prompt, encoding="utf-8")
        return {
            "prepared": {
                "task_dir": str(task_dir),
                "attempt_dir": str(attempt_dir),
                "attempt_id": attempt_id,
                "attempt_index": attempt_index,
                "attempt_kind": attempt_kind,
                "prompt": prompt,
                "prior_attempts": attempt_summaries,
            }
        }

    queue.set_status(task_id=task.task_id, status="diagnosing")
    diagnosis_dir = task_dir / "diagnosis"
    (diagnosis_dir / "workspace").mkdir(parents=True, exist_ok=True)
    (diagnosis_dir / "logs").mkdir(parents=True, exist_ok=True)
    records = sorted((task_dir / "attempts").glob("*/logs/*"))
    results = sorted((task_dir / "attempts").glob("*/result.json"))
    report_json = diagnosis_dir / "report.json"
    report_markdown = diagnosis_dir / "report.md"
    prompt = "\n".join(
        [
            "Analyze why all autonomous runtime construction attempts failed.",
            "Do not build, modify Docker state, or start services.",
            f"Write a concise diagnosis to {report_markdown} and structured findings",
            f"to {report_json}. Include verified facts, likely root causes,",
            "useful work from prior attempts, and the next recommended action.",
            "",
            "Original task:",
            task.prompt,
            "",
            "Attempt records:",
            *(f"- {path}" for path in [*records, *results]),
        ]
    )
    return {
        "prepared": {
            "task_dir": str(task_dir),
            "attempt_dir": str(diagnosis_dir),
            "attempt_id": None,
            "attempt_index": None,
            "attempt_kind": "diagnosis",
            "prompt": prompt,
            "prior_attempts": attempt_summaries,
        }
    }


def finish_attempt(
    *,
    queue: QueueStore,
    workspaces: WorkspaceManager,
    task: RuntimeTask,
    payload: dict[str, Any],
) -> dict[str, Any]:
    attempt_dir = Path(payload["attempt_dir"])
    attempt_id = payload.get("attempt_id")
    attempt_index = payload.get("attempt_index")
    attempt_kind = payload.get("attempt_kind")
    prior_attempts = payload.get("prior_attempts") or []
    agent_run = payload["agent_run"]
    workspaces.write_json(attempt_dir / "agent_run.json", agent_run)
    if attempt_kind == "diagnosis":
        final = {
            "task_id": task.task_id,
            "status": "failed",
            "attempts": prior_attempts,
            "diagnosis": {
                "agent_run": str(attempt_dir / "agent_run.json"),
                "report_json": str(attempt_dir / "report.json"),
                "report_markdown": str(attempt_dir / "report.md"),
            },
        }
        return {
            "final": write_final(
                queue=queue,
                workspaces=workspaces,
                task=task,
                final=final,
                status="failed",
            )
        }
    result_path = attempt_dir / "result.json"
    verification_path = attempt_dir / "verification.json"
    verification = None
    accepted = queue.accepted_submission(int(attempt_id))
    if verification_path.is_file():
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
    audit = payload.get("audit")
    audit_path = attempt_dir / "audit.json"
    if audit is not None:
        workspaces.write_json(audit_path, audit)
        queue.record_event(
            task_id=task.task_id,
            attempt_id=int(attempt_id),
            event=(
                "runtime_audit_passed"
                if audit.get("status") == "passed"
                else "runtime_audit_failed"
            ),
            detail=json.dumps(audit, ensure_ascii=False),
        )
    reason = None
    if audit is not None and audit.get("status") != "passed":
        reason = reason_from_mapping(audit.get("reason"))
    elif verification is not None and verification.get("status") != "passed":
        reason = reason_from_mapping(verification.get("reason"))
    elif accepted is None:
        submissions = queue.submissions_for(int(attempt_id))
        if submissions and isinstance(submissions[-1].get("reason_json"), str):
            reason = reason_from_mapping(json.loads(str(submissions[-1]["reason_json"])))
        if reason is None:
            reason = FailureReason(
                stage="metadata",
                code="submission_missing",
                message="agent did not produce an accepted result submission",
                evidence_path=str(attempt_dir / "agent_run.json"),
            )
    elif verification is not None and verification.get("status") == "passed" and audit is None:
        reason = FailureReason(
            stage="infrastructure",
            code="audit_result_missing",
            message="mechanical verification passed but no audit result was supplied",
            evidence_path=str(verification_path),
        )
    elif agent_run.get("error"):
        reason = FailureReason(
            stage="infrastructure",
            code="builder_agent_failed",
            message=str(agent_run["error"]),
            evidence_path=str(attempt_dir / "agent_run.json"),
        )
    error = reason.message if reason else None
    passed = (
        verification is not None
        and verification.get("status") == "passed"
        and audit is not None
        and audit.get("status") == "passed"
    )
    summary = {
        "attempt_id": attempt_id,
        "attempt_index": attempt_index,
        "attempt_kind": attempt_kind,
        "status": "passed" if passed else "failed",
        "agent": agent_run,
        "result_path": str(result_path) if result_path.is_file() else None,
        "verification_path": str(verification_path) if verification is not None else None,
        "audit_path": str(audit_path) if audit is not None else None,
        "error": error,
        "reason": reason.to_dict() if reason else None,
    }
    attempts = [*prior_attempts, summary]
    workspaces.write_json(attempt_dir / "attempt_summary.json", summary)
    queue.finish_attempt(
        attempt_id=int(attempt_id),
        status=summary["status"],
        error=error,
        agent_returncode=agent_run.get("returncode"),
        agent_timed_out=bool(agent_run.get("timed_out")),
        result_path=result_path if result_path.is_file() else None,
        verification_path=verification_path if verification is not None else None,
        audit_path=audit_path if audit is not None else None,
        reason=reason,
    )
    if passed:
        final = {
            "task_id": task.task_id,
            "status": "runtime_ready",
            "successful_attempt": f"{int(attempt_index):02d}-{attempt_kind}",
            "primary_image": verification.get("primary_image"),
            "launch_type": verification.get("launch_type"),
            "result_path": str(result_path),
            "verification_path": str(verification_path),
            "audit_path": str(audit_path),
            "attempts": attempts,
        }
        RuntimeVerifier().cleanup(attempt_dir=attempt_dir, result_path=result_path)
        return {
            "final": write_final(
                queue=queue,
                workspaces=workspaces,
                task=task,
                final=final,
                status="runtime_ready",
            )
        }
    RuntimeVerifier().cleanup(attempt_dir=attempt_dir, result_path=result_path)
    queue.set_status(task_id=task.task_id, status="running")
    return {"continue": True, "summary": summary}


def verify_attempt(
    *,
    queue: QueueStore,
    workspaces: WorkspaceManager,
    task: RuntimeTask,
    payload: dict[str, Any],
) -> dict[str, Any]:
    attempt_dir = Path(payload["attempt_dir"])
    attempt_id = int(payload["attempt_id"])
    result_path = attempt_dir / "result.json"
    verification_path = attempt_dir / "verification.json"
    accepted = queue.accepted_submission(attempt_id)
    if accepted is None or not result_path.is_file():
        return {
            "verified": False,
            "accepted": False,
            "result_path": str(result_path),
            "verification": None,
        }
    queue.set_status(task_id=task.task_id, status="verifying")
    verification = RuntimeVerifier().verify(
        attempt_dir=attempt_dir,
        result_path=result_path,
    )
    workspaces.write_json(verification_path, verification.to_dict())
    queue.record_event(
        task_id=task.task_id,
        attempt_id=attempt_id,
        event=(
            "mechanical_verification_passed"
            if verification.status == "passed"
            else "mechanical_verification_failed"
        ),
        detail=json.dumps(verification.to_dict(), ensure_ascii=False),
    )
    return {
        "verified": True,
        "accepted": True,
        "result_path": str(result_path),
        "verification_path": str(verification_path),
        "result": json.loads(result_path.read_text(encoding="utf-8")),
        "verification": verification.to_dict(),
    }


def main() -> int:
    payload = json.load(sys.stdin)
    action = payload["action"]
    queue = QueueStore(Path(payload["run_dir"]) / "queue.db")
    workspaces = WorkspaceManager(Path(payload["run_dir"]))
    if action == "claim":
        task = queue.claim(
            owner=payload["owner"],
            lease_seconds=int(payload["lease_seconds"]),
        )
        print(json.dumps(task.__dict__ if task else None, ensure_ascii=False))
    elif action == "heartbeat":
        ok = queue.heartbeat(
            task_id=payload["task_id"],
            owner=payload["owner"],
            lease_seconds=int(payload["lease_seconds"]),
        )
        print(json.dumps({"ok": ok}))
    elif action == "has_pending":
        print(json.dumps({"has_pending": queue.has_pending_tasks()}))
    elif action == "prepare_attempt":
        print(
            json.dumps(
                prepare_attempt(
                    queue=queue,
                    workspaces=workspaces,
                    task=task_from_dict(payload["task"]),
                ),
                ensure_ascii=False,
            )
        )
    elif action == "verify_attempt":
        print(
            json.dumps(
                verify_attempt(
                    queue=queue,
                    workspaces=workspaces,
                    task=task_from_dict(payload["task"]),
                    payload=payload,
                ),
                ensure_ascii=False,
            )
        )
    elif action == "finish_attempt":
        print(
            json.dumps(
                finish_attempt(
                    queue=queue,
                    workspaces=workspaces,
                    task=task_from_dict(payload["task"]),
                    payload=payload,
                ),
                ensure_ascii=False,
            )
        )
    else:
        raise SystemExit(f"unknown action: {action}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
