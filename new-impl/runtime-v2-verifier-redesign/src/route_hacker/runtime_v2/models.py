"""Small data contracts shared by the runtime-v2 modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


TaskStatus = Literal[
    "queued",
    "running",
    "verifying",
    "runtime_ready",
    "diagnosing",
    "failed",
    "cancelled",
]
AttemptKind = Literal["initial", "warm", "clean"]


@dataclass(frozen=True)
class FailureReason:
    stage: str
    code: str
    message: str
    evidence_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeTask:
    task_id: str
    prompt: str
    project_key: str | None = None
    priority: int = 0
    status: TaskStatus = "queued"
    attempt_index: int = 0


@dataclass(frozen=True)
class AgentResult:
    primary_image: str
    launch: dict[str, Any]
    probes: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_mapping(cls, value: Any) -> "AgentResult":
        if not isinstance(value, dict):
            raise ValueError("result must be a JSON object")
        primary_image = value.get("primary_image")
        launch = value.get("launch")
        probes = value.get("probes", [])
        if not isinstance(primary_image, str) or not primary_image.strip():
            raise ValueError("primary_image must be a non-empty string")
        if not isinstance(launch, dict):
            raise ValueError("launch must be a JSON object")
        launch_type = launch.get("type")
        if launch_type not in {"image", "compose", "script"}:
            raise ValueError("launch.type must be image, compose, or script")
        if not isinstance(probes, list):
            raise ValueError("probes must be a list")
        if not probes:
            raise ValueError("probes must contain at least one availability check")
        return cls(
            primary_image=primary_image.strip(),
            launch=launch,
            probes=probes,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttemptOutcome:
    attempt_id: int
    attempt_kind: AttemptKind
    status: str
    agent_returncode: int | None = None
    agent_timed_out: bool = False
    error: str | None = None
    result_path: str | None = None
    verification_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
