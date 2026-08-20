import json
import shlex
import stat
import subprocess
import sys
from pathlib import Path

from route_hacker.runtime_v2.agent import AgentRunResult
from route_hacker.runtime_v2.auditor import AuditResult
from route_hacker.runtime_v2.models import RuntimeTask
from route_hacker.runtime_v2.orchestrator import RuntimeV2Orchestrator
from route_hacker.runtime_v2.queue import QueueStore
from route_hacker.runtime_v2.submission import ResultSubmissionService
from route_hacker.runtime_v2.verifier import RuntimeVerifier
from route_hacker.runtime_v2.workspace import WorkspaceManager


class SubmittingAgent:
    def __init__(self):
        self.prompts: list[str] = []

    def run(
        self,
        *,
        task: RuntimeTask,
        attempt_kind: str,
        attempt_dir: Path,
        prompt: str,
        timeout_seconds: int,
    ) -> AgentRunResult:
        self.prompts.append(prompt)
        if attempt_kind == "clean" and attempt_dir.name == "diagnosis":
            return _agent_result(attempt_dir)
        start = attempt_dir / "workspace" / "start.sh"
        stop = attempt_dir / "workspace" / "stop.sh"
        check = attempt_dir / "workspace" / "check.sh"
        start.write_text("#!/bin/sh\nprintf ready > ready.txt\n", encoding="utf-8")
        stop.write_text("#!/bin/sh\nrm -f ready.txt\n", encoding="utf-8")
        check.write_text("#!/bin/sh\ntest -f ready.txt\n", encoding="utf-8")
        for path in (start, stop, check):
            path.chmod(path.stat().st_mode | stat.S_IXUSR)
        if task.provenance:
            source_root = attempt_dir / "workspace" / "source"
            source_root.mkdir()
            subprocess.run(["git", "init", "-q", str(source_root)], check=True)
            subprocess.run(["git", "-C", str(source_root), "config", "user.email", "test@example.test"], check=True)
            subprocess.run(["git", "-C", str(source_root), "config", "user.name", "Test"], check=True)
            (source_root / "README").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source_root), "add", "README"], check=True)
            subprocess.run(["git", "-C", str(source_root), "commit", "-qm", "fixture"], check=True)
            revision = subprocess.run(["git", "-C", str(source_root), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "-C", str(source_root), "remote", "add", "origin", task.provenance["repo_url"]], check=True)
            object.__setattr__(task, "provenance", {**task.provenance, "checkout_revision": revision})
            (attempt_dir / "workspace" / "source-attestation.json").write_text(
                json.dumps({**task.provenance, "source_root": str(source_root), "observed_revision": task.provenance["checkout_revision"]}),
                encoding="utf-8",
            )
        candidate = attempt_dir / "candidate-result.json"
        candidate.write_text(
            json.dumps(
                {
                    "primary_image": "example:latest",
                    "launch": {
                        "type": "script",
                        "start": "start.sh",
                        "stop": "stop.sh",
                    },
                    "probes": [{"type": "command", "command": ["./check.sh"]}],
                }
            ),
            encoding="utf-8",
        )
        command = _extract_submit_command(prompt)
        attempt_id = int(command[command.index("--attempt-id") + 1])
        run_dir = Path(command[command.index("--run-dir") + 1])
        ResultSubmissionService(QueueStore(run_dir / "queue.db")).submit(
            task_id=task.task_id,
            attempt_id=attempt_id,
            candidate_path=candidate,
        )
        return _agent_result(attempt_dir)


class PassingAuditor:
    def audit(self, **_: object) -> AuditResult:
        return AuditResult(
            status="passed",
            verdict="pass",
            attempts=1,
            command=["stub"],
            stdout_path="stdout",
            stderr_path="stderr",
            final_message_path="final",
            reproduction_commands=[],
            observations=[],
            evidence_paths=["verification.json"],
        )


class MissingSubmissionAgent:
    def run(
        self,
        *,
        task: RuntimeTask,
        attempt_kind: str,
        attempt_dir: Path,
        prompt: str,
        timeout_seconds: int,
    ) -> AgentRunResult:
        return _agent_result(attempt_dir)


class MissingAttestationSubmittingAgent(SubmittingAgent):
    def run(
        self,
        *,
        task: RuntimeTask,
        attempt_kind: str,
        attempt_dir: Path,
        prompt: str,
        timeout_seconds: int,
    ) -> AgentRunResult:
        original = task.provenance
        object.__setattr__(task, "provenance", None)
        try:
            return super().run(
                task=task,
                attempt_kind=attempt_kind,
                attempt_dir=attempt_dir,
                prompt=prompt,
                timeout_seconds=timeout_seconds,
            )
        finally:
            object.__setattr__(task, "provenance", original)


def _agent_result(attempt_dir: Path) -> AgentRunResult:
    return AgentRunResult(
        command=["stub"],
        returncode=0,
        timed_out=False,
        elapsed_seconds=0.01,
        stdout_path=str(attempt_dir / "stdout"),
        stderr_path=str(attempt_dir / "stderr"),
        final_message_path=str(attempt_dir / "final"),
    )


def _extract_submit_command(prompt: str) -> list[str]:
    prefix = "Required submission command: "
    line = next(line for line in prompt.splitlines() if line.startswith(prefix))
    return shlex.split(line[len(prefix) :])


def _claimed_task(queue: QueueStore) -> RuntimeTask:
    queue.submit(task_id="case-1", prompt="Build a runtime")
    task = queue.claim(owner="test", lease_seconds=120)
    assert task is not None
    return task


def test_orchestrator_requires_submission_verification_and_audit(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    queue = QueueStore(run_dir / "queue.db")
    task = _claimed_task(queue)
    agent = SubmittingAgent()
    orchestrator = RuntimeV2Orchestrator(
        queue=queue,
        workspaces=WorkspaceManager(run_dir),
        agent=agent,
        verifier=RuntimeVerifier(command_timeout_seconds=5),
        auditor=PassingAuditor(),
    )

    final = orchestrator.run_task(task)

    assert final["status"] == "runtime_ready"
    assert Path(final["verification_path"]).is_file()
    assert Path(final["audit_path"]).is_file()
    command = _extract_submit_command(agent.prompts[0])
    assert command[:3] == [sys.executable, "-m", "route_hacker.runtime_v2"]
    attempt = queue.attempts_for("case-1")[0]
    assert attempt["accepted_submission_id"] is not None
    assert attempt["audit_path"] == final["audit_path"]


def test_orchestrator_persists_submission_missing_reason(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    queue = QueueStore(run_dir / "queue.db")
    task = _claimed_task(queue)
    orchestrator = RuntimeV2Orchestrator(
        queue=queue,
        workspaces=WorkspaceManager(run_dir),
        agent=MissingSubmissionAgent(),
        verifier=RuntimeVerifier(command_timeout_seconds=5),
        auditor=PassingAuditor(),
    )

    final = orchestrator.run_task(task)

    assert final["status"] == "failed"
    assert final["reason"]["code"] == "submission_missing"
    attempts = queue.attempts_for("case-1")
    assert len(attempts) == 3
    assert all(
        json.loads(str(attempt["reason_json"]))["code"] == "submission_missing"
        for attempt in attempts
    )


def test_source_bound_runtime_rejects_missing_attestation(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    queue = QueueStore(run_dir / "queue.db")
    queue.submit(
        task_id="poc-case-1",
        prompt="Build exact source runtime",
        provenance={
            "identity_key": "org__repo::CVE-X",
            "case_id": "case-1",
            "finding_id": "finding::abc",
            "finding_sha256": "a" * 64,
            "repo_url": "https://example.test/repo.git",
            "checkout_revision": "deadbeef",
        },
    )
    task = queue.claim(owner="test", lease_seconds=120)
    assert task is not None
    orchestrator = RuntimeV2Orchestrator(
        queue=queue,
        workspaces=WorkspaceManager(run_dir),
        agent=MissingAttestationSubmittingAgent(),
        verifier=RuntimeVerifier(command_timeout_seconds=5),
        auditor=PassingAuditor(),
    )

    final = orchestrator.run_task(task)

    assert final["status"] == "failed"
    assert final["reason"]["code"] == "source_attestation_missing"
