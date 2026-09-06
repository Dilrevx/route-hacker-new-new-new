"""Retry orchestration for autonomous runtime construction."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .agent import AgentBackend, DiagnosticAgent, build_agent_prompt
from .auditor import RuntimeAuditor
from .models import AttemptKind, FailureReason, RuntimeTask
from .queue import QueueStore
from .verifier import RuntimeVerifier
from .workspace import WorkspaceManager


ATTEMPTS: tuple[tuple[int, AttemptKind], ...] = (
    (1, "initial"),
    (2, "warm"),
    (3, "clean"),
)


@dataclass(frozen=True)
class OrchestratorConfig:
    attempt_timeout_seconds: int = 7200
    diagnosis_timeout_seconds: int = 1800


class RuntimeV2Orchestrator:
    def __init__(
        self,
        *,
        queue: QueueStore,
        workspaces: WorkspaceManager,
        agent: AgentBackend,
        verifier: RuntimeVerifier,
        auditor: RuntimeAuditor,
        config: OrchestratorConfig | None = None,
    ):
        self.queue = queue
        self.workspaces = workspaces
        self.agent = agent
        self.verifier = verifier
        self.auditor = auditor
        self.config = config or OrchestratorConfig()

    def run_task(self, task: RuntimeTask) -> dict[str, Any]:
        task_dir = self.workspaces.initialize_task(task)
        attempt_summaries: list[dict[str, Any]] = []
        existing_attempts = {
            int(row["attempt_index"]): row
            for row in self.queue.attempts_for(task.task_id)
        }
        for attempt_index, attempt_kind in ATTEMPTS:
            existing = existing_attempts.get(attempt_index)
            if existing and existing["status"] == "failed":
                attempt_summaries.append(
                    self._load_attempt_summary(
                        task_dir=task_dir,
                        attempt_index=attempt_index,
                        attempt_kind=attempt_kind,
                        fallback=existing,
                    )
                )
                continue
            if existing and existing["status"] == "passed":
                resumed = self._resume_passed_attempt(
                    task=task,
                    task_dir=task_dir,
                    attempt_index=attempt_index,
                    attempt_kind=attempt_kind,
                    existing=existing,
                    attempt_summaries=attempt_summaries,
                )
                if resumed is not None:
                    return resumed

            if self.queue.cancellation_requested(task.task_id):
                final = {
                    "task_id": task.task_id,
                    "status": "cancelled",
                    "attempts": attempt_summaries,
                }
                return self._finish(task, final, "cancelled")

            attempt_dir = self.workspaces.prepare_attempt(
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
            attempt_id = self.queue.start_attempt(
                task_id=task.task_id,
                attempt_index=attempt_index,
                kind=attempt_kind,
                workspace=attempt_dir,
            )
            history_paths = self._retry_history(task_dir, attempt_index)
            submit_command = [
                sys.executable,
                "-m",
                "gca.runtime_v2",
                "submit-result",
                "--run-dir",
                str(self.workspaces.run_dir),
                "--task-id",
                task.task_id,
                "--attempt-id",
                str(attempt_id),
                "--candidate",
                str(attempt_dir / "candidate-result.json"),
            ]
            prompt = build_agent_prompt(
                task=task,
                attempt_kind=attempt_kind,
                attempt_dir=attempt_dir,
                submit_command=submit_command,
                history_paths=history_paths,
            )
            (attempt_dir / "agent_prompt.md").write_text(prompt, encoding="utf-8")
            agent_result = self.agent.run(
                task=task,
                attempt_kind=attempt_kind,
                attempt_dir=attempt_dir,
                prompt=prompt,
                timeout_seconds=self.config.attempt_timeout_seconds,
            )
            self.workspaces.write_json(
                attempt_dir / "agent_run.json",
                agent_result.to_dict(),
            )
            result_path = attempt_dir / "result.json"
            verification_path = attempt_dir / "verification.json"
            audit_path = attempt_dir / "audit.json"
            verification = None
            audit = None
            accepted = self.queue.accepted_submission(attempt_id)
            if accepted is not None and result_path.is_file():
                self.queue.set_status(task_id=task.task_id, status="verifying")
                verification = self.verifier.verify(
                    attempt_dir=attempt_dir,
                    result_path=result_path,
                )
                self.workspaces.write_json(
                    verification_path,
                    verification.to_dict(),
                )
                self.queue.record_event(
                    task_id=task.task_id,
                    attempt_id=attempt_id,
                    event=(
                        "mechanical_verification_passed"
                        if verification.status == "passed"
                        else "mechanical_verification_failed"
                    ),
                    detail=json.dumps(verification.to_dict(), ensure_ascii=False),
                )
                if verification.status == "passed":
                    audit = self.auditor.audit(
                        task=task,
                        attempt_dir=attempt_dir,
                        result_path=result_path,
                        verification=verification,
                    )
                    self.workspaces.write_json(audit_path, audit.to_dict())
                    self.queue.record_event(
                        task_id=task.task_id,
                        attempt_id=attempt_id,
                        event=(
                            "runtime_audit_passed"
                            if audit.status == "passed"
                            else "runtime_audit_failed"
                        ),
                        detail=json.dumps(audit.to_dict(), ensure_ascii=False),
                    )
            reason = self._attempt_reason(
                agent_error=agent_result.error,
                attempt_id=attempt_id,
                accepted=accepted,
                verification=verification,
                audit=audit,
                attempt_dir=attempt_dir,
            )
            error = reason.message if reason else None
            passed = (
                verification is not None
                and verification.status == "passed"
                and audit is not None
                and audit.status == "passed"
            )
            summary = {
                "attempt_id": attempt_id,
                "attempt_index": attempt_index,
                "attempt_kind": attempt_kind,
                "status": "passed" if passed else "failed",
                "agent": agent_result.to_dict(),
                "result_path": str(result_path) if result_path.is_file() else None,
                "verification_path": (
                    str(verification_path) if verification is not None else None
                ),
                "audit_path": str(audit_path) if audit is not None else None,
                "error": error,
                "reason": reason.to_dict() if reason else None,
            }
            attempt_summaries.append(summary)
            self.workspaces.write_json(attempt_dir / "attempt_summary.json", summary)
            self.queue.finish_attempt(
                attempt_id=attempt_id,
                status=summary["status"],
                error=error,
                agent_returncode=agent_result.returncode,
                agent_timed_out=agent_result.timed_out,
                result_path=result_path if result_path.is_file() else None,
                verification_path=verification_path if verification is not None else None,
                audit_path=audit_path if audit is not None else None,
                reason=reason,
            )
            if passed:
                final = {
                    "task_id": task.task_id,
                    "status": "runtime_ready",
                    "successful_attempt": f"{attempt_index:02d}-{attempt_kind}",
                    "primary_image": verification.primary_image,
                    "launch_type": verification.launch_type,
                    "result_path": str(result_path),
                    "verification_path": str(verification_path),
                    "audit_path": str(audit_path),
                    "attempts": attempt_summaries,
                }
                return self._finish(task, final, "runtime_ready")
            self.verifier.cleanup(attempt_dir=attempt_dir, result_path=result_path)
            self.queue.set_status(task_id=task.task_id, status="running")

        self.queue.set_status(task_id=task.task_id, status="diagnosing")
        diagnostic = DiagnosticAgent(self.agent).run(
            task=task,
            task_dir=task_dir,
            timeout_seconds=self.config.diagnosis_timeout_seconds,
        )
        self.workspaces.write_json(
            task_dir / "diagnosis" / "agent_run.json",
            diagnostic.to_dict(),
        )
        final = {
            "task_id": task.task_id,
            "status": "failed",
            "attempts": attempt_summaries,
            "reason": (
                attempt_summaries[-1].get("reason")
                if attempt_summaries
                else {
                    "stage": "infrastructure",
                    "code": "no_attempt_outcome",
                    "message": "no runtime attempt produced an outcome",
                    "evidence_path": str(task_dir / "diagnosis" / "agent_run.json"),
                }
            ),
            "diagnosis": {
                "agent_run": str(task_dir / "diagnosis" / "agent_run.json"),
                "report_json": str(task_dir / "diagnosis" / "report.json"),
                "report_markdown": str(task_dir / "diagnosis" / "report.md"),
            },
        }
        return self._finish(task, final, "failed")

    def _finish(
        self,
        task: RuntimeTask,
        final: dict[str, Any],
        status: str,
    ) -> dict[str, Any]:
        final_path = self.workspaces.task_dir(task.task_id) / "final.json"
        self.workspaces.write_json(final_path, final)
        self.queue.set_status(
            task_id=task.task_id,
            status=status,
            final_json=final_path,
            release_lease=True,
        )
        return final

    def _retry_history(self, task_dir: Path, attempt_index: int) -> list[Path]:
        if attempt_index <= 1:
            return []
        previous = sorted(
            path
            for path in (task_dir / "attempts").glob("[0-9][0-9]-*")
            if int(path.name.split("-", 1)[0]) < attempt_index
        )
        if not previous:
            return []
        prior = previous[-1]
        paths = [
            prior / "agent_run.json",
            prior / "attempt_summary.json",
            prior / "logs" / "agent.stdout.jsonl",
            prior / "logs" / "agent.stderr.log",
            prior / "logs" / "agent.final.txt",
            prior / "verification.json",
            prior / "audit.json",
        ]
        return [path for path in paths if path.exists()]

    def _attempt_reason(
        self,
        *,
        agent_error: str | None,
        attempt_id: int,
        accepted: dict[str, object] | None,
        verification: Any,
        audit: Any,
        attempt_dir: Path,
    ) -> FailureReason | None:
        if audit is not None:
            return audit.reason
        if verification is not None:
            if verification.reason is not None:
                return verification.reason
            if verification.status == "passed":
                return FailureReason(
                    stage="infrastructure",
                    code="audit_result_missing",
                    message="mechanical verification passed but no audit result was produced",
                    evidence_path=str(attempt_dir / "verification.json"),
                )
        if accepted is not None:
            return FailureReason(
                stage="infrastructure",
                code="audit_result_missing",
                message="accepted runtime did not produce a complete verification and audit result",
                evidence_path=str(attempt_dir / "agent_run.json"),
            )
        if accepted is None:
            submissions = self.queue.submissions_for(attempt_id)
            if submissions:
                last = submissions[-1]
                raw_reason = last.get("reason_json")
                if isinstance(raw_reason, str):
                    value = json.loads(raw_reason)
                    return FailureReason(**value)
            return FailureReason(
                stage="metadata",
                code="submission_missing",
                message="agent did not produce an accepted result submission",
                evidence_path=str(attempt_dir / "agent_run.json"),
            )
        if agent_error:
            return FailureReason(
                stage="infrastructure",
                code="builder_agent_failed",
                message=agent_error,
                evidence_path=str(attempt_dir / "agent_run.json"),
            )
        return None

    def _load_attempt_summary(
        self,
        *,
        task_dir: Path,
        attempt_index: int,
        attempt_kind: AttemptKind,
        fallback: dict[str, object],
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
        except (OSError, json.JSONDecodeError):
            pass
        return {
            "attempt_id": fallback["id"],
            "attempt_index": attempt_index,
            "attempt_kind": attempt_kind,
            "status": fallback["status"],
            "error": fallback.get("error"),
        }

    def _resume_passed_attempt(
        self,
        *,
        task: RuntimeTask,
        task_dir: Path,
        attempt_index: int,
        attempt_kind: AttemptKind,
        existing: dict[str, object],
        attempt_summaries: list[dict[str, Any]],
    ) -> dict[str, Any] | None:
        summary = self._load_attempt_summary(
            task_dir=task_dir,
            attempt_index=attempt_index,
            attempt_kind=attempt_kind,
            fallback=existing,
        )
        attempt_summaries.append(summary)
        verification_path_value = existing.get("verification_path")
        audit_path_value = existing.get("audit_path")
        result_path_value = existing.get("result_path")
        if not verification_path_value or not audit_path_value or not result_path_value:
            return None
        verification_path = Path(str(verification_path_value))
        audit_path = Path(str(audit_path_value))
        result_path = Path(str(result_path_value))
        try:
            verification = json.loads(verification_path.read_text(encoding="utf-8"))
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if verification.get("status") != "passed" or audit.get("status") != "passed":
            return None
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
        return self._finish(task, final, "runtime_ready")
