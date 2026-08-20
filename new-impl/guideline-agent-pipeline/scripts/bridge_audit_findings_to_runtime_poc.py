#!/usr/bin/env python3
"""Bridge formal stage-2 findings to Runtime V2 and independent PoC receipts.

This module deliberately does not call an LLM itself.  It writes an immutable
finding-level queue for Runtime V2, then reduces the independently produced
runtime, developer-PoC, and verifier receipts.  A Runtime V2 ``runtime_ready``
result is necessary runtime evidence, but never a vulnerability confirmation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "hcvr_ablation_a_confirmation.v1"
DEVELOPER_VERDICTS = {"CONFIRMED", "NOT_VULNERABLE", "INCONCLUSIVE", "BLOCKED"}
VERIFIER_VERDICTS = {"CONFIRMED", "REJECTED", "INVALID_POC", "INCONCLUSIVE", "BLOCKED"}


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON object required: {path}")
    return value


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"JSON object required at {path}:{number}")
            yield value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    os.replace(temporary, path)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_task_id(finding_id: str) -> str:
    return f"poc-{finding_id.split('::')[-1]}"


def finding_id(identity_key: str, index: int, finding: dict[str, Any]) -> str:
    digest = canonical_sha256({"identity_key": identity_key, "index": index, "finding": finding})
    return f"finding::{digest[:24]}"


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    return value.strip()


def build_runtime_prompt(request: dict[str, Any]) -> str:
    finding = request["finding"]
    return f"""Build a runnable environment for the exact vulnerability finding below.

This is a paper-evaluation confirmation task. Do not choose a different revision,
substitute a nearby release, or replace the product with a shim. Clone exactly:
- repository: {request['repo_url']}
- required checkout revision: {request['checkout_revision']}

Before submitting the Runtime V2 candidate, write
`source-attestation.json` inside the Runtime V2 attempt workspace with exactly:
{{
  "identity_key": "{request['identity_key']}",
  "case_id": "{request['case_id']}",
  "finding_id": "{request['finding_id']}",
  "finding_sha256": "{request['finding_sha256']}",
  "repo_url": "{request['repo_url']}",
  "checkout_revision": "{request['checkout_revision']}",
  "source_root": "<absolute checkout path inside the Runtime V2 attempt workspace>",
  "observed_revision": "<git rev-parse HEAD>"
}}
The observed revision must equal the required checkout revision. Preserve this
file and all runtime result, probe, and audit artifacts for the next PoC stage.

Stage-2 finding (a hypothesis to test, not a confirmation):
- title: {finding.get('title') or ''}
- location: {finding.get('file') or ''}:{finding.get('start_line') or ''}-{finding.get('end_line') or ''}
- symbol: {finding.get('symbol') or ''}
- rationale: {finding.get('rationale') or ''}
- missing condition: {finding.get('missing_or_incorrect_condition') or ''}
- sensitive effect: {finding.get('sensitive_effect') or ''}
- required PoC observation: {finding.get('poc_observation') or ''}
"""


def render_finding_audit_report(request: dict[str, Any]) -> str:
    """Materialize the exact stage-2 hypothesis consumed by both PoC roles."""
    finding = request["finding"]
    return f"""# Stage-2 finding for confirmation

This document is an audit hypothesis, not a confirmation. The PoC developer and
independent verifier must test it only against the frozen source identity below.

- Identity: {request['identity_key']}
- Case: {request['case_id']}
- Finding: {request['finding_id']}
- Finding SHA-256: {request['finding_sha256']}
- Repository: {request['repo_url']}
- Frozen revision: {request['checkout_revision']}

## Claim

- Title: {finding.get('title') or ''}
- Location: {finding.get('file') or ''}:{finding.get('start_line') or ''}-{finding.get('end_line') or ''}
- Symbol: {finding.get('symbol') or ''}
- Rationale: {finding.get('rationale') or ''}
- Missing or incorrect condition: {finding.get('missing_or_incorrect_condition') or ''}
- Sensitive effect: {finding.get('sensitive_effect') or ''}
- Required PoC observation: {finding.get('poc_observation') or ''}
"""


def prepare_requests(stage2_results: Path, output_dir: Path) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in read_jsonl(stage2_results):
        if row.get("state") != "completed":
            continue
        identity = require_string(row.get("identity_key"), "identity_key")
        repo_url = require_string(row.get("repo_url"), f"{identity}.repo_url")
        checkout_revision = require_string(row.get("checkout_revision"), f"{identity}.checkout_revision")
        case_id = require_string(row.get("case_id"), f"{identity}.case_id")
        findings = row.get("findings") or []
        if not isinstance(findings, list):
            raise ValueError(f"{identity}.findings must be a list")
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                raise ValueError(f"{identity}.findings[{index}] must be an object")
            identifier = finding_id(identity, index, finding)
            if identifier in seen:
                raise ValueError(f"duplicate finding identity: {identifier}")
            seen.add(identifier)
            finding_sha = canonical_sha256(finding)
            request = {
                "schema_version": SCHEMA_VERSION,
                "identity_key": identity,
                "case_id": case_id,
                "finding_id": identifier,
                "finding_index": index,
                "finding_sha256": finding_sha,
                "stage2_case_receipt": str(stage2_results.resolve()),
                "stage2_case_receipt_sha256": sha256_file(stage2_results),
                "repo_url": repo_url,
                "checkout_revision": checkout_revision,
                "finding": finding,
                "runtime_task_id": safe_task_id(identifier),
            }
            request["runtime_prompt"] = build_runtime_prompt(request)
            finding_dir = output_dir / "findings" / request["runtime_task_id"]
            audit_report_path = finding_dir / "audit-report.md"
            audit_report_path.parent.mkdir(parents=True, exist_ok=True)
            audit_report_path.write_text(render_finding_audit_report(request), encoding="utf-8")
            request["audit_report_path"] = str(audit_report_path.resolve())
            request["audit_report_sha256"] = sha256_file(audit_report_path)
            requests.append(request)
            write_json(finding_dir / "confirmation-request.json", request)
    return requests


def runtime_queue_row(request: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": request["runtime_task_id"],
        "project_key": request["identity_key"].split("::", 1)[0],
        "prompt": request["runtime_prompt"],
        "provenance": {field: request[field] for field in (
            "identity_key", "case_id", "finding_id", "finding_sha256",
            "repo_url", "checkout_revision",
        )},
    }


def existing_file(path: str, label: str) -> Path:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"{label} is missing: {resolved}")
    return resolved


def validate_runtime(request: dict[str, Any], runtime_run_dir: Path) -> dict[str, Any]:
    task_id = request["runtime_task_id"]
    final_path = runtime_run_dir / "tasks" / task_id / "final.json"
    final = read_json(existing_file(str(final_path), "runtime final receipt"))
    if final.get("status") != "runtime_ready":
        raise ValueError(f"runtime task {task_id} is not runtime_ready")
    result_path = existing_file(require_string(final.get("result_path"), "runtime result_path"), "runtime result")
    verification_path = existing_file(require_string(final.get("verification_path"), "runtime verification_path"), "runtime verification")
    audit_path = existing_file(require_string(final.get("audit_path"), "runtime audit_path"), "runtime audit")
    verification = read_json(verification_path)
    audit = read_json(audit_path)
    if verification.get("status") != "passed" or audit.get("status") != "passed":
        raise ValueError(f"runtime task {task_id} lacks passed verification/audit")
    attestation_path = result_path.parent / "workspace" / "source-attestation.json"
    attestation = read_json(existing_file(str(attestation_path), "source attestation"))
    for field in ("identity_key", "case_id", "finding_id", "finding_sha256", "repo_url", "checkout_revision"):
        if attestation.get(field) != request.get(field):
            raise ValueError(f"runtime source attestation mismatch for {field}")
    if attestation.get("observed_revision") != request["checkout_revision"]:
        raise ValueError("runtime source attestation observed_revision does not match checkout_revision")
    return {
        "task_id": task_id,
        "final_path": str(final_path.resolve()),
        "final_sha256": sha256_file(final_path),
        "result_path": str(result_path),
        "result_sha256": sha256_file(result_path),
        "verification_path": str(verification_path),
        "verification_sha256": sha256_file(verification_path),
        "audit_path": str(audit_path),
        "audit_sha256": sha256_file(audit_path),
        "source_attestation_path": str(attestation_path.resolve()),
        "source_attestation_sha256": sha256_file(attestation_path),
    }


def validate_poc_receipt(
    receipt: dict[str, Any],
    request: dict[str, Any],
    *,
    role: str,
) -> dict[str, Any]:
    allowed = DEVELOPER_VERDICTS if role == "developer" else VERIFIER_VERDICTS
    verdict = receipt.get("verdict")
    if verdict not in allowed:
        raise ValueError(f"{role} verdict must be one of {sorted(allowed)}")
    for field in ("identity_key", "case_id", "finding_id", "finding_sha256", "checkout_revision"):
        if receipt.get(field) != request.get(field):
            raise ValueError(f"{role} receipt mismatch for {field}")
    if role == "verifier" and receipt.get("developer_receipt_sha256") is None:
        raise ValueError("verifier receipt must bind developer_receipt_sha256")
    if verdict == "CONFIRMED":
        artifact = existing_file(require_string(receipt.get("artifact_path"), f"{role}.artifact_path"), f"{role} artifact")
        evidence = receipt.get("evidence_paths")
        if not isinstance(evidence, list) or not evidence:
            raise ValueError(f"{role} CONFIRMED receipt needs non-empty evidence_paths")
        evidence_paths = [str(existing_file(require_string(item, f"{role}.evidence_path"), f"{role} evidence")) for item in evidence]
        reproduce = require_string(receipt.get("reproduce_command"), f"{role}.reproduce_command")
        return {"verdict": verdict, "artifact_path": str(artifact), "evidence_paths": evidence_paths, "reproduce_command": reproduce}
    return {"verdict": verdict}


def reduce_confirmation(
    requests_path: Path,
    runtime_run_dir: Path,
    receipts_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    requests = {row["finding_id"]: row for row in read_jsonl(requests_path)}
    stage2_hashes = {str(row.get("stage2_case_receipt_sha256") or "") for row in requests.values()}
    if len(stage2_hashes) > 1:
        raise ValueError("confirmation requests bind more than one stage-2 receipt")
    receipt_rows = {row.get("finding_id"): row for row in read_jsonl(receipts_path)}
    results: list[dict[str, Any]] = []
    for identifier, request in requests.items():
        receipt = receipt_rows.get(identifier)
        result: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "finding_id": identifier,
            "finding_sha256": request["finding_sha256"],
            "identity_key": request["identity_key"],
            "case_id": request["case_id"],
            "confirmed": False,
            "status": "INCONCLUSIVE",
        }
        try:
            result["runtime"] = validate_runtime(request, runtime_run_dir)
            if not isinstance(receipt, dict):
                raise ValueError("missing combined PoC receipt")
            developer_path = existing_file(require_string(receipt.get("developer_receipt"), "developer_receipt"), "developer receipt")
            verifier_path = existing_file(require_string(receipt.get("verifier_receipt"), "verifier_receipt"), "verifier receipt")
            developer = validate_poc_receipt(read_json(developer_path), request, role="developer")
            verifier_raw = read_json(verifier_path)
            if verifier_raw.get("developer_receipt_sha256") != sha256_file(developer_path):
                raise ValueError("verifier receipt does not bind the exact developer receipt")
            verifier = validate_poc_receipt(verifier_raw, request, role="verifier")
            result.update({
                "developer_receipt_path": str(developer_path),
                "developer_receipt_sha256": sha256_file(developer_path),
                "developer": developer,
                "verifier_receipt_path": str(verifier_path),
                "verifier_receipt_sha256": sha256_file(verifier_path),
                "verifier": verifier,
                "status": verifier["verdict"],
                "confirmed": developer["verdict"] == "CONFIRMED" and verifier["verdict"] == "CONFIRMED",
            })
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            result.update({"status": "INVALID_RECEIPT", "error": f"{type(exc).__name__}: {exc}"})
        write_json(output_dir / "results" / f"{safe_task_id(identifier)}.json", result)
        results.append(result)
    write_jsonl(output_dir / "confirmation_results.jsonl", results)
    counts: dict[str, int] = {}
    for row in results:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    summary = {
        "schema_version": SCHEMA_VERSION,
        "finding_count": len(results),
        "confirmed_count": sum(bool(row["confirmed"]) for row in results),
        "confirmation_requests": str(requests_path.resolve()),
        "confirmation_requests_sha256": sha256_file(requests_path),
        "stage2_results_sha256": next(iter(stage2_hashes), ""),
        "status_counts": counts,
        "results": str((output_dir / "confirmation_results.jsonl").resolve()),
    }
    write_json(output_dir / "confirmation_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--stage2-results", type=Path, required=True)
    prepare.add_argument("--output-dir", type=Path, required=True)
    reduce = commands.add_parser("reduce")
    reduce.add_argument("--requests", type=Path, required=True)
    reduce.add_argument("--runtime-run-dir", type=Path, required=True)
    reduce.add_argument("--poc-receipts", type=Path, required=True)
    reduce.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        requests = prepare_requests(args.stage2_results.resolve(), args.output_dir.resolve())
        requests_path = args.output_dir.resolve() / "confirmation_requests.jsonl"
        queue_path = args.output_dir.resolve() / "runtime_v2_tasks.jsonl"
        write_jsonl(requests_path, requests)
        write_jsonl(queue_path, (runtime_queue_row(request) for request in requests))
        write_json(args.output_dir.resolve() / "prepare_summary.json", {
            "schema_version": SCHEMA_VERSION,
            "stage2_results": str(args.stage2_results.resolve()),
            "stage2_results_sha256": sha256_file(args.stage2_results.resolve()),
            "finding_count": len(requests),
            "confirmation_requests": str(requests_path),
            "runtime_v2_tasks": str(queue_path),
        })
        return
    print(json.dumps(reduce_confirmation(args.requests.resolve(), args.runtime_run_dir.resolve(), args.poc_receipts.resolve(), args.output_dir.resolve()), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
