"""Attempt-scoped result submission and metadata validation."""

from __future__ import annotations

import json
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import AgentResult, FailureReason
from .queue import QueueStore


@dataclass(frozen=True)
class SubmissionResult:
    accepted: bool
    submission_id: int
    submission_index: int
    snapshot_path: str
    result_path: str | None = None
    reason: FailureReason | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "submission_id": self.submission_id,
            "submission_index": self.submission_index,
            "snapshot_path": self.snapshot_path,
            "result_path": self.result_path,
            "reason": self.reason.to_dict() if self.reason else None,
        }


class SubmissionValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ResultSubmissionService:
    def __init__(self, queue: QueueStore):
        self.queue = queue

    def submit(
        self,
        *,
        task_id: str,
        attempt_id: int,
        candidate_path: Path,
    ) -> SubmissionResult:
        attempt = self.queue.get_attempt(attempt_id)
        if attempt is None:
            raise ValueError(f"attempt does not exist: {attempt_id}")
        if attempt["task_id"] != task_id:
            raise ValueError(f"attempt {attempt_id} does not belong to task {task_id}")
        if attempt["status"] != "running":
            raise ValueError(f"attempt {attempt_id} is not running")

        attempt_dir = Path(str(attempt["workspace"])).resolve()
        workspace = (attempt_dir / "workspace").resolve()
        source_path = candidate_path.resolve()
        try:
            source_path.relative_to(attempt_dir)
        except ValueError as exc:
            raise ValueError("candidate result must be inside the attempt directory") from exc

        submissions_dir = attempt_dir / "submissions"
        submissions_dir.mkdir(parents=True, exist_ok=True)
        snapshot_path = submissions_dir / f"submission-{uuid.uuid4().hex}.json"
        reason: FailureReason | None = None
        normalized: dict[str, Any] | None = None
        try:
            raw = source_path.read_bytes()
            snapshot_path.write_bytes(raw)
            value = json.loads(raw.decode("utf-8"))
            result = AgentResult.from_mapping(value)
            normalized = self._validate(result=result, workspace=workspace)
        except OSError as exc:
            reason = FailureReason(
                stage="metadata",
                code="result_unreadable",
                message=f"{type(exc).__name__}: {exc}",
                evidence_path=str(snapshot_path if snapshot_path.exists() else source_path),
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            reason = FailureReason(
                stage="metadata",
                code="invalid_json",
                message=f"{type(exc).__name__}: {exc}",
                evidence_path=str(snapshot_path),
            )
        except SubmissionValidationError as exc:
            reason = FailureReason(
                stage="metadata",
                code=exc.code,
                message=str(exc),
                evidence_path=str(snapshot_path),
            )
        except ValueError as exc:
            reason = FailureReason(
                stage="metadata",
                code="invalid_result_schema",
                message=str(exc),
                evidence_path=str(snapshot_path),
            )

        result_path = attempt_dir / "result.json"
        if reason is None and normalized is not None:
            temporary = result_path.with_suffix(".json.tmp")
            temporary.write_text(
                json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            temporary.replace(result_path)
            shutil.copyfile(result_path, snapshot_path)

        record = self.queue.record_submission_check(
            attempt_id=attempt_id,
            source_path=source_path,
            snapshot_path=snapshot_path,
            status="accepted" if reason is None else "rejected",
            reason=reason,
            result_path=result_path if reason is None else None,
        )
        self.queue.record_event(
            task_id=task_id,
            attempt_id=attempt_id,
            event="submission_accepted" if reason is None else "submission_rejected",
            detail=json.dumps(
                reason.to_dict() if reason else {"result_path": str(result_path)},
                ensure_ascii=False,
            ),
        )
        return SubmissionResult(
            accepted=reason is None,
            submission_id=int(record["id"]),
            submission_index=int(record["submission_index"]),
            snapshot_path=str(snapshot_path),
            result_path=str(result_path) if reason is None else None,
            reason=reason,
        )

    def _validate(self, *, result: AgentResult, workspace: Path) -> dict[str, Any]:
        launch = dict(result.launch)
        launch_type = launch["type"]
        if launch_type == "image":
            image = launch.get("image") or result.primary_image
            if not isinstance(image, str) or not image.strip():
                raise SubmissionValidationError(
                    "image_missing",
                    "image launch requires launch.image or primary_image",
                )
            launch["image"] = image.strip()
            ports = launch.get("ports", [])
            if not isinstance(ports, list) or any(
                not isinstance(port, (str, int)) for port in ports
            ):
                raise SubmissionValidationError(
                    "image_ports_invalid",
                    "launch.ports must be a list of strings or integers",
                )
            args = launch.get("args", [])
            if not isinstance(args, list):
                raise SubmissionValidationError(
                    "image_args_invalid",
                    "launch.args must be a list",
                )
        elif launch_type == "compose":
            launch["file"] = self._relative_existing_path(
                workspace=workspace,
                value=launch.get("file"),
                code="compose_file_missing",
                label="launch.file",
            )
        else:
            launch["start"] = self._relative_existing_path(
                workspace=workspace,
                value=launch.get("start"),
                code="start_script_missing",
                label="launch.start",
            )
            if launch.get("stop") is not None:
                launch["stop"] = self._relative_existing_path(
                    workspace=workspace,
                    value=launch.get("stop"),
                    code="stop_script_missing",
                    label="launch.stop",
                )

        probes = [
            self._validate_probe(
                probe=probe,
                workspace=workspace,
                index=index,
                launch_type=str(launch_type),
            )
            for index, probe in enumerate(result.probes)
        ]
        return {
            "primary_image": result.primary_image,
            "launch": launch,
            "probes": probes,
        }

    def _validate_probe(
        self,
        *,
        probe: Any,
        workspace: Path,
        index: int,
        launch_type: str,
    ) -> dict[str, Any]:
        if not isinstance(probe, dict):
            raise SubmissionValidationError(
                "probe_not_object",
                f"probes[{index}] must be an object",
            )
        normalized = dict(probe)
        probe_type = normalized.get("type")
        if probe_type == "http":
            url = normalized.get("url")
            parsed = urlparse(url) if isinstance(url, str) else None
            if parsed is None or parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise SubmissionValidationError(
                    "http_probe_url_invalid",
                    f"probes[{index}].url must be a full HTTP or HTTPS URL",
                )
        elif probe_type == "tcp":
            if not isinstance(normalized.get("host"), str) or not normalized["host"]:
                raise SubmissionValidationError(
                    "tcp_probe_host_invalid",
                    f"probes[{index}].host must be a non-empty string",
                )
            port = normalized.get("port")
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                raise SubmissionValidationError(
                    "tcp_probe_port_invalid",
                    f"probes[{index}].port must be an integer from 1 to 65535",
                )
        elif probe_type in {"command", "exec"}:
            command = normalized.get("command")
            if not isinstance(command, list) or not command or any(
                not isinstance(part, (str, int, float)) for part in command
            ):
                raise SubmissionValidationError(
                    "command_probe_invalid",
                    f"probes[{index}].command must be a non-empty argv list",
                )
            if probe_type == "exec" and launch_type == "compose":
                service = normalized.get("service")
                if not isinstance(service, str) or not service:
                    raise SubmissionValidationError(
                        "exec_probe_service_invalid",
                        f"probes[{index}].service must name a Compose service",
                    )
            if probe_type == "exec" and launch_type == "script":
                raise SubmissionValidationError(
                    "exec_probe_launch_invalid",
                    f"probes[{index}] cannot use exec with a script launch",
                )
        elif probe_type == "log":
            if not isinstance(normalized.get("container"), str) or not normalized["container"]:
                raise SubmissionValidationError(
                    "log_probe_container_invalid",
                    f"probes[{index}].container must be a non-empty string",
                )
            if not isinstance(normalized.get("contains"), str):
                raise SubmissionValidationError(
                    "log_probe_contains_invalid",
                    f"probes[{index}].contains must be a string",
                )
        elif probe_type == "liveness":
            seconds = normalized.get("seconds", 10)
            if not isinstance(seconds, (int, float)) or isinstance(seconds, bool) or seconds < 0:
                raise SubmissionValidationError(
                    "liveness_probe_seconds_invalid",
                    f"probes[{index}].seconds must be a non-negative number",
                )
        else:
            raise SubmissionValidationError(
                "probe_type_unknown",
                f"probes[{index}].type is unsupported: {probe_type!r}",
            )
        timeout = normalized.get("timeout_seconds")
        if timeout is not None and (
            not isinstance(timeout, (int, float))
            or isinstance(timeout, bool)
            or timeout <= 0
        ):
            raise SubmissionValidationError(
                "probe_timeout_invalid",
                f"probes[{index}].timeout_seconds must be positive",
            )
        return normalized

    def _relative_existing_path(
        self,
        *,
        workspace: Path,
        value: Any,
        code: str,
        label: str,
    ) -> str:
        if not isinstance(value, str) or not value.strip():
            raise SubmissionValidationError(code, f"{label} must be a non-empty string")
        path = Path(value)
        resolved = path.resolve() if path.is_absolute() else (workspace / path).resolve()
        try:
            relative = resolved.relative_to(workspace)
        except ValueError as exc:
            raise SubmissionValidationError(
                "launch_path_outside_workspace",
                f"{label} must resolve inside the attempt workspace",
            ) from exc
        if not resolved.is_file():
            raise SubmissionValidationError(code, f"{label} does not exist: {resolved}")
        return str(relative)
