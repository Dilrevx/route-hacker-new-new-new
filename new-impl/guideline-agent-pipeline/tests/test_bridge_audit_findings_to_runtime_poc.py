from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "bridge_audit_findings_to_runtime_poc.py"


def load_module():
    spec = importlib.util.spec_from_file_location("bridge_audit_findings_to_runtime_poc", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def stage2_row() -> dict:
    return {
        "identity_key": "owner__repo::CVE-1",
        "case_id": "case::1",
        "repo_url": "https://github.com/owner/repo.git",
        "checkout_revision": "a" * 40,
        "state": "completed",
        "findings": [
            {
                "title": "missing authorization",
                "file": "src/App.java",
                "start_line": 10,
                "end_line": 20,
                "symbol": "App.get",
                "rationale": "missing resource ownership guard",
                "missing_or_incorrect_condition": "verify resource ownership",
                "sensitive_effect": "returns another tenant's data",
                "poc_observation": "cross-tenant response body",
            }
        ],
    }


def prepare_request(tmp_path: Path):
    module = load_module()
    stage2 = tmp_path / "full" / "case_results.jsonl"
    stage2.parent.mkdir(parents=True)
    stage2.write_text(json.dumps(stage2_row()) + "\n", encoding="utf-8")
    requests = module.prepare_requests(stage2, tmp_path / "bridge")
    assert len(requests) == 1
    assert "Do not choose a different revision" in requests[0]["runtime_prompt"]
    assert "source-attestation.json" in requests[0]["runtime_prompt"]
    audit_report = Path(requests[0]["audit_report_path"])
    assert audit_report.is_file()
    assert module.sha256_file(audit_report) == requests[0]["audit_report_sha256"]
    assert (audit_report.parent / "confirmation-request.json").is_file()
    return module, requests[0]


def prepare_runtime(tmp_path: Path, request: dict, *, revision: str | None = None) -> Path:
    runtime = tmp_path / "runtime"
    attempt = runtime / "tasks" / request["runtime_task_id"] / "attempts" / "01-initial"
    result = attempt / "result.json"
    verification = attempt / "verification.json"
    audit = attempt / "audit.json"
    attestation = attempt / "workspace" / "source-attestation.json"
    write_json(result, {"primary_image": "example:latest", "launch": {"type": "script"}, "probes": [{"type": "liveness"}]})
    write_json(verification, {"status": "passed"})
    write_json(audit, {"status": "passed"})
    write_json(attestation, {
        "identity_key": request["identity_key"],
        "case_id": request["case_id"],
        "finding_id": request["finding_id"],
        "finding_sha256": request["finding_sha256"],
        "repo_url": request["repo_url"],
        "checkout_revision": request["checkout_revision"],
        "observed_revision": revision or request["checkout_revision"],
    })
    write_json(runtime / "tasks" / request["runtime_task_id"] / "final.json", {
        "status": "runtime_ready",
        "result_path": str(result),
        "verification_path": str(verification),
        "audit_path": str(audit),
    })
    return runtime


def prepare_poc_receipts(tmp_path: Path, module, request: dict, *, verifier_verdict: str = "CONFIRMED", evidence: bool = True) -> Path:
    artifact = tmp_path / "poc" / "reproduce.sh"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("#!/bin/sh\n", encoding="utf-8")
    evidence_path = tmp_path / "poc" / "evidence.log"
    evidence_path.write_text("observed effect\n", encoding="utf-8")
    common = {field: request[field] for field in ("identity_key", "case_id", "finding_id", "finding_sha256", "checkout_revision")}
    developer = tmp_path / "developer.json"
    write_json(developer, {**common, "verdict": "CONFIRMED", "artifact_path": str(artifact), "reproduce_command": "./reproduce.sh", "evidence_paths": [str(evidence_path)]})
    verifier = tmp_path / "verifier.json"
    verifier_value = {**common, "verdict": verifier_verdict, "developer_receipt_sha256": module.sha256_file(developer)}
    if evidence:
        verifier_value.update({"artifact_path": str(artifact), "reproduce_command": "./reproduce.sh", "evidence_paths": [str(evidence_path)]})
    write_json(verifier, verifier_value)
    combined = tmp_path / "combined.jsonl"
    combined.write_text(json.dumps({"finding_id": request["finding_id"], "developer_receipt": str(developer), "verifier_receipt": str(verifier)}) + "\n", encoding="utf-8")
    return combined


def test_reduce_requires_runtime_lineage_and_independent_confirmed_receipts(tmp_path: Path):
    module, request = prepare_request(tmp_path)
    runtime = prepare_runtime(tmp_path, request)
    combined = prepare_poc_receipts(tmp_path, module, request)
    requests = tmp_path / "requests.jsonl"
    requests.write_text(json.dumps(request) + "\n", encoding="utf-8")

    summary = module.reduce_confirmation(requests, runtime, combined, tmp_path / "reduced")

    assert summary["confirmed_count"] == 1
    result = json.loads((tmp_path / "reduced" / "confirmation_results.jsonl").read_text(encoding="utf-8"))
    assert result["confirmed"] is True
    assert result["status"] == "CONFIRMED"
    assert result["runtime"]["source_attestation_sha256"]


def test_reduce_rejects_revision_drift_even_when_runtime_is_ready(tmp_path: Path):
    module, request = prepare_request(tmp_path)
    runtime = prepare_runtime(tmp_path, request, revision="b" * 40)
    combined = prepare_poc_receipts(tmp_path, module, request)
    requests = tmp_path / "requests.jsonl"
    requests.write_text(json.dumps(request) + "\n", encoding="utf-8")

    module.reduce_confirmation(requests, runtime, combined, tmp_path / "reduced")

    result = json.loads((tmp_path / "reduced" / "confirmation_results.jsonl").read_text(encoding="utf-8"))
    assert result["confirmed"] is False
    assert result["status"] == "INVALID_RECEIPT"
    assert "observed_revision" in result["error"]


def test_reduce_does_not_confirm_when_independent_verifier_rejects(tmp_path: Path):
    module, request = prepare_request(tmp_path)
    runtime = prepare_runtime(tmp_path, request)
    combined = prepare_poc_receipts(tmp_path, module, request, verifier_verdict="REJECTED")
    requests = tmp_path / "requests.jsonl"
    requests.write_text(json.dumps(request) + "\n", encoding="utf-8")

    summary = module.reduce_confirmation(requests, runtime, combined, tmp_path / "reduced")

    assert summary["confirmed_count"] == 0
    result = json.loads((tmp_path / "reduced" / "confirmation_results.jsonl").read_text(encoding="utf-8"))
    assert result["status"] == "REJECTED"
    assert result["confirmed"] is False


def test_reduce_rejects_confirmed_verdict_without_evidence(tmp_path: Path):
    module, request = prepare_request(tmp_path)
    runtime = prepare_runtime(tmp_path, request)
    combined = prepare_poc_receipts(tmp_path, module, request, evidence=False)
    requests = tmp_path / "requests.jsonl"
    requests.write_text(json.dumps(request) + "\n", encoding="utf-8")

    module.reduce_confirmation(requests, runtime, combined, tmp_path / "reduced")

    result = json.loads((tmp_path / "reduced" / "confirmation_results.jsonl").read_text(encoding="utf-8"))
    assert result["confirmed"] is False
    assert result["status"] == "INVALID_RECEIPT"
    assert "verifier" in result["error"]
