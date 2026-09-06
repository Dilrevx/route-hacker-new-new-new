"""Independent launcher and probe runner for agent-produced environments."""

from __future__ import annotations

import errno
import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Sequence

from .models import AgentResult, FailureReason
from .workspace import attempt_resource_name


@dataclass(frozen=True)
class VerificationResult:
    status: str
    launch_type: str | None
    primary_image: str | None
    started: bool
    probe_results: list[dict[str, Any]] = field(default_factory=list)
    launch_info: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    reason: FailureReason | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["reason"] = self.reason.to_dict() if self.reason else None
        return value


class RuntimeVerifier:
    def __init__(
        self,
        *,
        command_timeout_seconds: int = 120,
        probe_poll_seconds: float = 1.0,
    ):
        self.command_timeout_seconds = command_timeout_seconds
        self.probe_poll_seconds = probe_poll_seconds

    def verify(self, *, attempt_dir: Path, result_path: Path) -> VerificationResult:
        try:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            result = AgentResult.from_mapping(value)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            reason = FailureReason(
                stage="metadata",
                code="invalid_accepted_result",
                message=f"invalid result.json: {exc}",
                evidence_path=str(result_path),
            )
            return VerificationResult(
                status="failed",
                launch_type=None,
                primary_image=None,
                started=False,
                error=reason.message,
                reason=reason,
            )

        launch_type = str(result.launch["type"])
        try:
            self.cleanup(attempt_dir=attempt_dir, result_path=result_path)
            launch_info = self._start(attempt_dir=attempt_dir, result=result)
            probe_results = [
                self._run_probe(
                    attempt_dir=attempt_dir,
                    probe=probe,
                    launch_info=launch_info,
                )
                for probe in result.probes
            ]
            failed = [probe for probe in probe_results if not probe["passed"]]
            if failed:
                storage_exhausted = any(
                    self._mapping_reports_storage_exhaustion(probe)
                    for probe in failed
                )
                reason = FailureReason(
                    stage="infrastructure" if storage_exhausted else "probe",
                    code="storage_exhausted" if storage_exhausted else "probe_failed",
                    message=(
                        "storage exhausted while running availability probes"
                        if storage_exhausted
                        else f"{len(failed)} probe(s) failed"
                    ),
                    evidence_path=str(attempt_dir / "verification.json"),
                )
                return VerificationResult(
                    status="failed",
                    launch_type=launch_type,
                    primary_image=result.primary_image,
                    started=True,
                    probe_results=probe_results,
                    launch_info=launch_info,
                    error=reason.message,
                    reason=reason,
                )
            return VerificationResult(
                status="passed",
                launch_type=launch_type,
                primary_image=result.primary_image,
                started=True,
                probe_results=probe_results,
                launch_info=launch_info,
            )
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            evidence_path = self._write_launch_error(attempt_dir=attempt_dir, exc=exc)
            storage_exhausted = self._is_storage_exhausted(exc)
            reason = FailureReason(
                stage="infrastructure" if storage_exhausted else "launch",
                code=(
                    "storage_exhausted"
                    if storage_exhausted
                    else self._launch_error_code(exc)
                ),
                message=self._launch_error_message(exc),
                evidence_path=str(evidence_path),
            )
            return VerificationResult(
                status="failed",
                launch_type=launch_type,
                primary_image=result.primary_image,
                started=False,
                error=reason.message,
                reason=reason,
            )

    def _launch_error_message(self, exc: BaseException) -> str:
        message = f"{type(exc).__name__}: {exc}"
        if isinstance(exc, subprocess.CalledProcessError):
            detail = (exc.stderr or exc.stdout or "").strip()
            if detail:
                message = f"{message}: {detail[-2000:]}"
        return message

    def _write_launch_error(self, *, attempt_dir: Path, exc: BaseException) -> Path:
        evidence_path = attempt_dir / "launch-error.json"
        value: dict[str, Any] = {
            "error_type": type(exc).__name__,
            "message": str(exc),
        }
        if isinstance(exc, subprocess.CalledProcessError):
            value.update(
                {
                    "command": [str(part) for part in exc.cmd],
                    "returncode": exc.returncode,
                    "stdout": (exc.stdout or "")[-12000:],
                    "stderr": (exc.stderr or "")[-12000:],
                }
            )
        elif isinstance(exc, subprocess.TimeoutExpired):
            value.update(
                {
                    "command": [str(part) for part in exc.cmd],
                    "timeout_seconds": exc.timeout,
                    "stdout": self._text_tail(exc.stdout),
                    "stderr": self._text_tail(exc.stderr),
                }
            )
        try:
            evidence_path.write_text(
                json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError:
            return attempt_dir / "verification.json"
        return evidence_path

    def _text_tail(self, value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return value[-12000:]

    def _launch_error_code(self, exc: BaseException) -> str:
        if isinstance(exc, subprocess.TimeoutExpired):
            return "launch_timeout"
        if isinstance(exc, subprocess.CalledProcessError):
            return "launch_command_failed"
        if isinstance(exc, ValueError):
            return "launch_declaration_invalid"
        return "launch_failed"

    def _is_storage_exhausted(self, exc: BaseException) -> bool:
        if isinstance(exc, OSError) and exc.errno in {errno.ENOSPC, errno.EDQUOT}:
            return True
        values = [str(exc)]
        if isinstance(exc, subprocess.CalledProcessError):
            values.extend([exc.stdout or "", exc.stderr or ""])
        message = " ".join(values).lower()
        return any(
            marker in message
            for marker in (
                "no space left on device",
                "disk quota exceeded",
                "enospc",
                "edquot",
            )
        )

    def _mapping_reports_storage_exhaustion(self, value: dict[str, Any]) -> bool:
        message = " ".join(
            str(value.get(field) or "")
            for field in ("error", "stdout", "stderr")
        ).lower()
        return any(
            marker in message
            for marker in (
                "no space left on device",
                "disk quota exceeded",
                "enospc",
                "edquot",
            )
        )

    def cleanup(self, *, attempt_dir: Path, result_path: Path) -> None:
        try:
            value = json.loads(result_path.read_text(encoding="utf-8"))
            result = AgentResult.from_mapping(value)
        except (OSError, json.JSONDecodeError, ValueError):
            return
        try:
            launch = result.launch
            if launch["type"] == "compose":
                compose_file = self._resolve(attempt_dir, launch.get("file"))
                project_name = self._resource_name(attempt_dir)
                self._run(
                    [
                        "docker",
                        "compose",
                        "-p",
                        project_name,
                        "-f",
                        str(compose_file),
                        "down",
                    ],
                    cwd=compose_file.parent,
                    check=False,
                )
            elif launch["type"] == "image":
                self._run(
                    ["docker", "rm", "-f", self._resource_name(attempt_dir)],
                    cwd=attempt_dir / "workspace",
                    check=False,
                )
            elif launch["type"] == "script" and launch.get("stop"):
                stop_script = self._resolve(attempt_dir, launch.get("stop"))
                self._run([str(stop_script)], cwd=stop_script.parent, check=False)
        except (OSError, subprocess.SubprocessError, ValueError):
            return

    def _start(
        self,
        *,
        attempt_dir: Path,
        result: AgentResult,
    ) -> dict[str, Any]:
        launch = result.launch
        launch_type = launch["type"]
        if launch_type == "image":
            image = launch.get("image") or result.primary_image
            if not isinstance(image, str) or not image:
                raise ValueError("image launch requires an image")
            container_name = self._resource_name(attempt_dir)
            command = [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                container_name,
                "--label",
                "gca.runtime-v2=true",
            ]
            for port in launch.get("ports", []):
                command.extend(["-p", str(port)])
            command.append(image)
            args = launch.get("args", [])
            if isinstance(args, list):
                command.extend(str(arg) for arg in args)
            self._run(command, cwd=attempt_dir / "workspace")
            return {"container_name": container_name}
        if launch_type == "compose":
            compose_file = self._resolve(attempt_dir, launch.get("file"))
            project_name = self._resource_name(attempt_dir)
            self._run(
                [
                    "docker",
                    "compose",
                    "-p",
                    project_name,
                    "-f",
                    str(compose_file),
                    "up",
                    "-d",
                ],
                cwd=compose_file.parent,
            )
            return {
                "compose_file": str(compose_file),
                "compose_project": project_name,
            }
        start_script = self._resolve(attempt_dir, launch.get("start"))
        self._run([str(start_script)], cwd=start_script.parent)
        return {
            "start_script": str(start_script),
            "stop_script": launch.get("stop"),
        }

    def _run_probe(
        self,
        *,
        attempt_dir: Path,
        probe: Any,
        launch_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if not isinstance(probe, dict):
            return {"passed": False, "error": "probe must be an object"}
        probe_type = probe.get("type")
        if probe_type == "liveness":
            try:
                seconds = float(probe.get("seconds", 10))
                if seconds < 0:
                    raise ValueError("liveness seconds must not be negative")
                time.sleep(seconds)
                return {
                    "type": "liveness",
                    "passed": True,
                    "seconds": seconds,
                    "attempts": 1,
                    "elapsed_seconds": seconds,
                }
            except (TypeError, ValueError) as exc:
                return {
                    "type": probe_type,
                    "passed": False,
                    "attempts": 1,
                    "elapsed_seconds": 0.0,
                    "error": f"{type(exc).__name__}: {exc}",
                }

        timeout = float(probe.get("timeout_seconds", 10))
        deadline = time.monotonic() + timeout
        started = time.monotonic()
        attempts = 0
        result: dict[str, Any] = {
            "type": probe_type,
            "passed": False,
            "error": "probe did not run",
        }
        while True:
            attempts += 1
            remaining = max(0.001, deadline - time.monotonic())
            result = self._run_probe_once(
                attempt_dir=attempt_dir,
                probe=probe,
                operation_timeout=min(5.0, remaining),
                launch_info=launch_info,
            )
            if result["passed"] or time.monotonic() >= deadline:
                break
            time.sleep(min(self.probe_poll_seconds, max(0.0, deadline - time.monotonic())))
        result["attempts"] = attempts
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        return result

    def _run_probe_once(
        self,
        *,
        attempt_dir: Path,
        probe: dict[str, Any],
        operation_timeout: float,
        launch_info: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        probe_type = probe.get("type")
        try:
            if probe_type == "http":
                try:
                    with urllib.request.urlopen(
                        str(probe["url"]),
                        timeout=operation_timeout,
                    ) as response:
                        status = response.status
                except urllib.error.HTTPError as exc:
                    status = exc.code
                return {"type": "http", "passed": 200 <= status < 500, "status": status}
            if probe_type == "tcp":
                with socket.create_connection(
                    (str(probe["host"]), int(probe["port"])),
                    timeout=operation_timeout,
                ):
                    pass
                return {"type": "tcp", "passed": True}
            if probe_type == "command":
                command = probe.get("command")
                if not isinstance(command, list) or not command:
                    raise ValueError("command probe requires a non-empty command list")
                completed = self._run(
                    [str(part) for part in command],
                    cwd=attempt_dir / "workspace",
                    check=False,
                    timeout=min(self.command_timeout_seconds, operation_timeout),
                )
                return {
                    "type": probe_type,
                    "passed": completed.returncode == 0,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout[-4000:],
                    "stderr": completed.stderr[-4000:],
                }
            if probe_type == "exec":
                command = probe.get("command")
                if not isinstance(command, list) or not command:
                    raise ValueError("exec probe requires a non-empty command list")
                context = launch_info or {}
                if context.get("compose_project") and context.get("compose_file"):
                    service = probe.get("service")
                    if not isinstance(service, str) or not service:
                        raise ValueError("compose exec probe requires a non-empty service")
                    exec_command = [
                        "docker",
                        "compose",
                        "-p",
                        str(context["compose_project"]),
                        "-f",
                        str(context["compose_file"]),
                        "exec",
                        "-T",
                        service,
                        *[str(part) for part in command],
                    ]
                elif context.get("container_name"):
                    exec_command = [
                        "docker",
                        "exec",
                        str(context["container_name"]),
                        *[str(part) for part in command],
                    ]
                else:
                    raise ValueError("exec probe requires an image or compose launch")
                completed = self._run(
                    exec_command,
                    cwd=attempt_dir / "workspace",
                    check=False,
                    timeout=min(self.command_timeout_seconds, operation_timeout),
                )
                return {
                    "type": "exec",
                    "passed": completed.returncode == 0,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout[-4000:],
                    "stderr": completed.stderr[-4000:],
                }
            if probe_type == "log":
                completed = self._run(
                    ["docker", "logs", str(probe["container"])],
                    cwd=attempt_dir / "workspace",
                    check=False,
                    timeout=min(self.command_timeout_seconds, operation_timeout),
                )
                needle = str(probe["contains"])
                output = completed.stdout + completed.stderr
                return {
                    "type": "log",
                    "passed": needle in output,
                    "contains": needle,
                }
            return {"type": probe_type, "passed": False, "error": "unknown probe type"}
        except (KeyError, OSError, ValueError, subprocess.SubprocessError) as exc:
            return {
                "type": probe_type,
                "passed": False,
                "error": f"{type(exc).__name__}: {exc}",
            }

    def _resolve(self, attempt_dir: Path, value: Any) -> Path:
        if not isinstance(value, str) or not value:
            raise ValueError("launch file path must be a non-empty string")
        path = Path(value)
        if not path.is_absolute():
            path = attempt_dir / "workspace" / path
        if not path.exists():
            raise ValueError(f"launch file does not exist: {path}")
        return path.resolve()

    def _resource_name(self, attempt_dir: Path) -> str:
        return attempt_resource_name(attempt_dir)

    def _run(
        self,
        command: Sequence[str],
        *,
        cwd: Path,
        check: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            cwd=cwd,
            text=True,
            capture_output=True,
            timeout=self.command_timeout_seconds if timeout is None else timeout,
            check=check,
        )
