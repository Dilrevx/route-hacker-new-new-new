import json
from pathlib import Path

from gca.runtime_v2.auditor import LocalRuntimeAuditor
from gca.runtime_v2.models import RuntimeTask
from gca.runtime_v2.verifier import VerificationResult


class StubAuditor(LocalRuntimeAuditor):
    def __init__(self, outputs: list[dict[str, object]]):
        super().__init__(command=("stub",), max_attempts=len(outputs))
        self.outputs = outputs
        self.calls = 0

    def _run(
        self,
        *,
        command: list[str],
        prompt: str,
        cwd: Path,
        stdout_path: Path,
        stderr_path: Path,
    ) -> tuple[int | None, bool, str | None]:
        output = self.outputs[self.calls]
        self.calls += 1
        final_path = Path(command[command.index("--output-last-message") + 1])
        final_path.write_text(json.dumps(output), encoding="utf-8")
        stdout_path.write_text(prompt, encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        return 0, False, None


def _verification() -> VerificationResult:
    return VerificationResult(
        status="passed",
        launch_type="script",
        primary_image="example:latest",
        started=True,
        probe_results=[{"type": "command", "passed": True}],
        launch_info={"start_script": "start.sh"},
    )


def _attempt(tmp_path: Path) -> Path:
    attempt_dir = tmp_path / "attempt"
    (attempt_dir / "workspace").mkdir(parents=True)
    (attempt_dir / "result.json").write_text("{}", encoding="utf-8")
    (attempt_dir / "verification.json").write_text("{}", encoding="utf-8")
    return attempt_dir


def test_auditor_accepts_pass_result(tmp_path: Path) -> None:
    attempt_dir = _attempt(tmp_path)
    auditor = StubAuditor(
        [
            {
                "verdict": "pass",
                "reproduction_commands": [],
                "observations": [],
                "evidence_paths": ["verification.json"],
            }
        ]
    )

    result = auditor.audit(
        task=RuntimeTask(task_id="case-1", prompt="Build runtime"),
        attempt_dir=attempt_dir,
        result_path=attempt_dir / "result.json",
        verification=_verification(),
    )

    assert result.status == "passed"
    assert result.verdict == "pass"
    assert result.reason is None


def test_auditor_requires_reproducible_reject_evidence(tmp_path: Path) -> None:
    attempt_dir = _attempt(tmp_path)
    auditor = StubAuditor(
        [
            {
                "verdict": "reject",
                "code": "wrong_service",
                "message": "probe reached an unrelated service",
                "reproduction_commands": [["curl", "http://127.0.0.1:8080/"]],
                "observations": ["response identifies a different application"],
                "evidence_paths": ["verification.json"],
            }
        ]
    )

    result = auditor.audit(
        task=RuntimeTask(task_id="case-1", prompt="Build runtime"),
        attempt_dir=attempt_dir,
        result_path=attempt_dir / "result.json",
        verification=_verification(),
    )

    assert result.status == "failed"
    assert result.reason is not None
    assert result.reason.stage == "audit"
    assert result.reason.code == "wrong_service"


def test_auditor_retries_invalid_reject_then_reports_infrastructure_failure(
    tmp_path: Path,
) -> None:
    attempt_dir = _attempt(tmp_path)
    invalid = {
        "verdict": "reject",
        "code": "guess",
        "message": "looks wrong",
        "reproduction_commands": [],
        "observations": [],
        "evidence_paths": [],
    }
    auditor = StubAuditor([invalid, invalid])

    result = auditor.audit(
        task=RuntimeTask(task_id="case-1", prompt="Build runtime"),
        attempt_dir=attempt_dir,
        result_path=attempt_dir / "result.json",
        verification=_verification(),
    )

    assert auditor.calls == 2
    assert result.status == "failed"
    assert result.verdict is None
    assert result.reason is not None
    assert result.reason.code == "audit_infrastructure_failed"


def test_remote_auditor_requires_evidence_file_to_exist(tmp_path: Path) -> None:
    attempt_dir = _attempt(tmp_path)
    reject = {
        "verdict": "reject",
        "code": "wrong_service",
        "message": "probe reached an unrelated service",
        "reproduction_commands": [["curl", "http://127.0.0.1:8080/"]],
        "observations": ["response identifies a different application"],
        "evidence_paths": ["missing-evidence.txt"],
    }
    auditor = StubAuditor([reject, reject])
    auditor._remote_evidence_exists = lambda **_: False  # type: ignore[method-assign]
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()

    result = auditor.audit_evidence(
        task=RuntimeTask(task_id="case-1", prompt="Build runtime"),
        attempt_dir=attempt_dir,
        result_path=attempt_dir / "result.json",
        verification=_verification(),
        artifact_dir=audit_dir,
        execution_cwd=audit_dir,
        remote_host="example-host",
    )

    assert auditor.calls == 2
    assert result.status == "failed"
    assert result.verdict is None
    assert result.reason is not None
    assert result.reason.code == "audit_infrastructure_failed"
    assert "remote audit evidence does not exist" in result.reason.message
