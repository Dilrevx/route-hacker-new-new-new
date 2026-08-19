"""Independent AI review of mechanically verified runtime claims."""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from .models import FailureReason, RuntimeTask
from .verifier import VerificationResult


@dataclass(frozen=True)
class AuditResult:
    status: str
    verdict: str | None
    attempts: int
    command: list[str]
    stdout_path: str
    stderr_path: str
    final_message_path: str
    reproduction_commands: list[list[str]]
    observations: list[str]
    evidence_paths: list[str]
    error: str | None = None
    reason: FailureReason | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["reason"] = self.reason.to_dict() if self.reason else None
        return value


class RuntimeAuditor(Protocol):
    def audit(
        self,
        *,
        task: RuntimeTask,
        attempt_dir: Path,
        result_path: Path,
        verification: VerificationResult,
    ) -> AuditResult: ...


class TraeXRuntimeAuditor:
    def __init__(
        self,
        *,
        command: Sequence[str] = ("traex",),
        extra_args: Sequence[str] = (),
        timeout_seconds: int = 900,
        max_attempts: int = 2,
        environment: Mapping[str, str] | None = None,
    ):
        self.command = [str(part) for part in command]
        self.extra_args = [str(part) for part in extra_args]
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max_attempts
        self.environment = dict(environment or {})

    def audit(
        self,
        *,
        task: RuntimeTask,
        attempt_dir: Path,
        result_path: Path,
        verification: VerificationResult,
    ) -> AuditResult:
        return self.audit_evidence(
            task=task,
            attempt_dir=attempt_dir,
            result_path=result_path,
            verification=verification,
            artifact_dir=attempt_dir / "audit",
            execution_cwd=attempt_dir / "workspace",
        )

    def audit_evidence(
        self,
        *,
        task: RuntimeTask,
        attempt_dir: Path,
        result_path: Path,
        verification: VerificationResult,
        artifact_dir: Path,
        execution_cwd: Path,
        remote_host: str | None = None,
    ) -> AuditResult:
        audit_dir = artifact_dir
        audit_dir.mkdir(parents=True, exist_ok=True)
        last_error = "audit did not run"
        command: list[str] = []
        stdout_path = audit_dir / "auditor.stdout.jsonl"
        stderr_path = audit_dir / "auditor.stderr.log"
        final_message_path = audit_dir / "auditor.final.json"
        for audit_attempt in range(1, self.max_attempts + 1):
            suffix = f".{audit_attempt}" if self.max_attempts > 1 else ""
            stdout_path = audit_dir / f"auditor{suffix}.stdout.jsonl"
            stderr_path = audit_dir / f"auditor{suffix}.stderr.log"
            final_message_path = audit_dir / f"auditor{suffix}.final.json"
            command = self._command(final_message_path)
            prompt = self._prompt(
                task=task,
                attempt_dir=attempt_dir,
                result_path=result_path,
                verification=verification,
                remote_host=remote_host,
            )
            returncode, timed_out, error = self._run(
                command=command,
                prompt=prompt,
                cwd=execution_cwd,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
            if timed_out:
                last_error = f"auditor timed out after {self.timeout_seconds} seconds"
                continue
            if returncode != 0:
                last_error = error or f"auditor exited with {returncode}"
                continue
            try:
                value = json.loads(final_message_path.read_text(encoding="utf-8"))
                return self._parse(
                    value=value,
                    attempt_dir=attempt_dir,
                    attempts=audit_attempt,
                    command=command,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                    final_message_path=final_message_path,
                    require_local_evidence=remote_host is None,
                    remote_host=remote_host,
                )
            except (OSError, json.JSONDecodeError, ValueError) as exc:
                last_error = f"invalid auditor output: {type(exc).__name__}: {exc}"

        reason = FailureReason(
            stage="infrastructure",
            code="audit_infrastructure_failed",
            message=last_error,
            evidence_path=str(stderr_path),
        )
        return AuditResult(
            status="failed",
            verdict=None,
            attempts=self.max_attempts,
            command=command,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            final_message_path=str(final_message_path),
            reproduction_commands=[],
            observations=[],
            evidence_paths=[str(stderr_path)],
            error=reason.message,
            reason=reason,
        )

    def _parse(
        self,
        *,
        value: Any,
        attempt_dir: Path,
        attempts: int,
        command: list[str],
        stdout_path: Path,
        stderr_path: Path,
        final_message_path: Path,
        require_local_evidence: bool,
        remote_host: str | None,
    ) -> AuditResult:
        if not isinstance(value, dict):
            raise ValueError("audit result must be a JSON object")
        verdict = value.get("verdict")
        if verdict not in {"pass", "reject", "inconclusive"}:
            raise ValueError("verdict must be pass, reject, or inconclusive")
        reproduction_commands = value.get("reproduction_commands", [])
        observations = value.get("observations", [])
        evidence_paths = value.get("evidence_paths", [])
        if not isinstance(reproduction_commands, list) or any(
            not isinstance(item, list)
            or not item
            or any(not isinstance(part, str) for part in item)
            for item in reproduction_commands
        ):
            raise ValueError("reproduction_commands must be a list of non-empty argv lists")
        if not isinstance(observations, list) or any(
            not isinstance(item, str) or not item.strip() for item in observations
        ):
            raise ValueError("observations must be a list of non-empty strings")
        if not isinstance(evidence_paths, list) or any(
            not isinstance(item, str) or not item.strip() for item in evidence_paths
        ):
            raise ValueError("evidence_paths must be a list of non-empty strings")
        resolved_evidence = [
            str(
                self._resolve_evidence(
                    attempt_dir=attempt_dir,
                    value=item,
                    require_local=require_local_evidence,
                    remote_host=remote_host,
                )
            )
            for item in evidence_paths
        ]
        if verdict in {"reject", "inconclusive"}:
            if not reproduction_commands or not observations or not resolved_evidence:
                raise ValueError(
                    f"{verdict} requires reproduction_commands, observations, and evidence_paths"
                )
            message = value.get("message")
            if not isinstance(message, str) or not message.strip():
                raise ValueError(f"{verdict} requires a non-empty message")
            reason = FailureReason(
                stage="audit",
                code=str(
                    value.get("code")
                    or (
                        "runtime_claim_rejected"
                        if verdict == "reject"
                        else "audit_inconclusive"
                    )
                ),
                message=message.strip(),
                evidence_path=resolved_evidence[0],
            )
            return AuditResult(
                status="failed",
                verdict=verdict,
                attempts=attempts,
                command=command,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                final_message_path=str(final_message_path),
                reproduction_commands=reproduction_commands,
                observations=observations,
                evidence_paths=resolved_evidence,
                error=reason.message,
                reason=reason,
            )
        return AuditResult(
            status="passed",
            verdict=verdict,
            attempts=attempts,
            command=command,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            final_message_path=str(final_message_path),
            reproduction_commands=reproduction_commands,
            observations=observations,
            evidence_paths=resolved_evidence,
        )

    def _resolve_evidence(
        self,
        *,
        attempt_dir: Path,
        value: str,
        require_local: bool,
        remote_host: str | None,
    ) -> Path:
        path = Path(value)
        if require_local:
            resolved = (
                path.resolve() if path.is_absolute() else (attempt_dir / path).resolve()
            )
        else:
            resolved = path if path.is_absolute() else attempt_dir / path
        try:
            resolved.relative_to(attempt_dir.resolve() if require_local else attempt_dir)
        except ValueError as exc:
            raise ValueError("audit evidence must be inside the attempt directory") from exc
        if require_local and not resolved.exists():
            raise ValueError(f"audit evidence does not exist: {resolved}")
        if remote_host is not None and not self._remote_evidence_exists(
            remote_host=remote_host,
            path=resolved,
        ):
            raise ValueError(f"remote audit evidence does not exist: {resolved}")
        return resolved

    def _remote_evidence_exists(self, *, remote_host: str, path: Path) -> bool:
        completed = subprocess.run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=20",
                remote_host,
                f"test -f {shlex.quote(str(path))}",
            ],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        return completed.returncode == 0

    def _command(self, final_message_path: Path) -> list[str]:
        executable = Path(self.command[0]).name
        command = [
            *self.command,
            "exec",
            "--json",
            "--ephemeral",
            "--dangerously-bypass-approvals-and-sandbox",
            "--skip-git-repo-check",
            "--output-last-message",
            str(final_message_path),
            *self.extra_args,
        ]
        if executable in {"traex", "traecli"}:
            command[2:2] = ["--ignore-user-config", "--ignore-rules"]
        if executable in {"codex", "traex", "traecli"}:
            command.append("-")
        return command

    def _prompt(
        self,
        *,
        task: RuntimeTask,
        attempt_dir: Path,
        result_path: Path,
        verification: VerificationResult,
        remote_host: str | None,
    ) -> str:
        verification_path = attempt_dir / "verification.json"
        return "\n".join(
            [
                "Independently audit a runtime-ready or PoC-ready claim after mechanical launch and probes passed.",
                "Do not modify files, containers, images, services, or the submitted runtime.",
                "Use only read-only diagnostic commands.",
                "",
                "If this is only a runtime build task, pass when the evidence supports the",
                "claimed main application runtime. Reject only with a concrete reproducible",
                "counterexample, not speculation or a preference for stronger probes.",
                "",
                "If the task, submitted result, or evidence describes a vulnerability PoC,",
                "audit whether the observed PoC effect actually demonstrates the vulnerability",
                "described by the task. Compare the vulnerability id/description, target files,",
                "patch or trace evidence in the task, the PoC's claimed effect, and the runtime",
                "observations. Do not pass only because the PoC produced a security-looking",
                "signal. A PoC that triggers a different bug, a generic dangerous behavior, or",
                "only proves the runtime is reachable must be reject or inconclusive.",
                "Use inconclusive when the PoC ran but the available evidence is insufficient",
                "to prove it matches the described vulnerability.",
                "",
                f"Task: {task.task_id}",
                f"Attempt directory: {attempt_dir}",
                f"Submitted result: {result_path}",
                f"Mechanical verification: {verification_path}",
                f"Mechanical status: {verification.status}",
                f"Launch info: {json.dumps(verification.launch_info, ensure_ascii=False)}",
                f"Probe results: {json.dumps(verification.probe_results, ensure_ascii=False)}",
                (
                    f"All inspected runtime artifacts are on remote host {remote_host}. "
                    f"Use ssh {remote_host} for read-only diagnostic commands."
                    if remote_host
                    else "Runtime artifacts are available in the local attempt directory."
                ),
                "",
                "Write exactly one JSON object to the configured final-message file.",
                'Pass: {"verdict":"pass","reproduction_commands":[],"observations":[],',
                '       "evidence_paths":["verification.json"]}',
                'Reject: {"verdict":"reject","code":"stable_code","message":"reason",',
                '         "reproduction_commands":[["command","arg"]],',
                '         "observations":["actual observed fact"],',
                '         "evidence_paths":["path under attempt directory"]}',
                'Inconclusive: {"verdict":"inconclusive","code":"stable_code","message":"reason",',
                '         "reproduction_commands":[["command","arg"]],',
                '         "observations":["actual observed fact"],',
                '         "evidence_paths":["path under attempt directory"]}',
                "",
                "Original runtime task:",
                task.prompt,
            ]
        )

    def _run(
        self,
        *,
        command: list[str],
        prompt: str,
        cwd: Path,
        stdout_path: Path,
        stderr_path: Path,
    ) -> tuple[int | None, bool, str | None]:
        environment = os.environ.copy()
        environment.update(self.environment)
        started = time.monotonic()
        del started
        with stdout_path.open("w", encoding="utf-8") as stdout, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            try:
                process = subprocess.Popen(
                    command,
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.PIPE,
                    stdout=stdout,
                    stderr=stderr,
                    text=True,
                    start_new_session=True,
                )
                try:
                    process.communicate(input=prompt, timeout=self.timeout_seconds)
                    return process.returncode, False, None
                except subprocess.TimeoutExpired:
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
                    return 124, True, None
            except OSError as exc:
                return None, False, f"{type(exc).__name__}: {exc}"
