#!/usr/bin/env python3
"""Run one focused audit per HCVR case anchor from the new unified QA file."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any, Iterable


DECISION_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Decision(?:\*\*)?\s*:\s*"
    r"(?:\*\*)?(risk|no-risk)(?:\*\*)?\s*$"
)
CONFIDENCE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Confidence(?:\*\*)?\s*:\s*"
    r"(?:\*\*)?(0(?:\.\d+)?|1(?:\.0+)?)(?:\*\*)?\s*$"
)

GUIDELINES = {
    "authentication_session_token_validation": (
        "Audit whether authentication, session, token, OAuth, cookie, or "
        "capability validation is missing, incomplete, bound to the wrong "
        "principal, reusable outside its intended scope, or skipped before a "
        "sensitive operation."
    ),
    "authorization_bypass": (
        "Audit whether the code performs a sensitive read, write, mutation, "
        "administrative action, or document/resource operation without an "
        "authorization decision that is bound to the current principal and "
        "the target object."
    ),
    "business_state_precondition": (
        "Audit whether a sensitive state transition or effect can occur "
        "without enforcing the required business precondition, lifecycle "
        "state, quota, ownership state, or operation ordering."
    ),
    "concurrent_object_lifecycle": (
        "Audit whether the code observes, checks, caches, or reuses a mutable "
        "object, request, principal, path, thread-local, or shared state and "
        "then performs a sensitive effect after that object may have been "
        "changed, replaced, cleared, or confused."
    ),
    "file_permission_temp_resource": (
        "Audit whether file, temporary resource, upload/download, extraction, "
        "permission, path, or filesystem handling creates an unauthorized "
        "read/write/delete/execute effect through weak permissions, unsafe "
        "temporary locations, path confusion, or non-stable resource binding."
    ),
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_report(text: str) -> tuple[str | None, float | None]:
    decisions = DECISION_RE.findall(text)
    confidences = CONFIDENCE_RE.findall(text)
    decision = decisions[-1].lower() if decisions else None
    confidence = float(confidences[-1]) if confidences else None
    return decision, confidence


def has_command_execution(events: str) -> bool:
    for line in events.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        item = event.get("item") or {}
        if item.get("type") == "command_execution":
            return True
    return False


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    input_text: str,
    timeout: int,
) -> tuple[int | None, str, str]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=cwd,
        env=env,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(input=input_text, timeout=timeout)
        return process.returncode, output or "", "completed"
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            more_output, _ = process.communicate(timeout=5)
            output += more_output or ""
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            more_output, _ = process.communicate()
            output += more_output or ""
        return process.returncode, output, "timeout"


def safe_slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_")[:120]


def load_selected_cases(qa_path: Path, limit: int, skip: int) -> list[dict[str, Any]]:
    qa = read_json(qa_path)
    identities = list(qa["added_identities"])[skip : skip + limit]
    case_path = Path(qa["files"]["cases"]["path"])
    cases_by_identity = {
        row["identity_key"]: row
        for row in read_jsonl(case_path)
        if row.get("identity_key") in set(identities)
    }
    missing = [identity for identity in identities if identity not in cases_by_identity]
    if missing:
        raise ValueError(f"selected identities missing from cases file: {missing}")
    return [cases_by_identity[identity] for identity in identities]


def pick_anchor(case: dict[str, Any], anchor_index: int) -> dict[str, Any]:
    anchors = case.get("recall_anchors") or []
    if not anchors:
        raise ValueError(f"case has no recall anchors: {case.get('identity_key')}")
    if anchor_index >= len(anchors):
        raise ValueError(
            f"anchor index {anchor_index} absent for {case.get('identity_key')}"
        )
    return anchors[anchor_index]


def clone_or_fetch(repo_url: str, repo_dir: Path) -> None:
    if repo_dir.exists():
        subprocess.run(["git", "-C", str(repo_dir), "fetch", "--all", "--tags"], check=True)
        return
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "clone", "--no-checkout", repo_url, str(repo_dir)], check=True)


def materialize_snapshot(repo_dir: Path, commit: str, snapshot: Path) -> None:
    if snapshot.exists():
        raise FileExistsError(f"refusing existing source snapshot: {snapshot}")
    observed = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", f"{commit}^{{commit}}"],
        text=True,
    ).strip()
    if observed != commit:
        raise ValueError(f"repository does not resolve expected commit: {commit}")
    snapshot.mkdir(parents=True)
    archive = snapshot.parent / f".{snapshot.name}.tar"
    try:
        subprocess.run(
            [
                "git",
                "-C",
                str(repo_dir),
                "archive",
                "--format=tar",
                f"--output={archive}",
                commit,
            ],
            check=True,
        )
        with tarfile.open(archive) as handle:
            handle.extractall(snapshot, filter="data")
    finally:
        archive.unlink(missing_ok=True)


def ensure_snapshot(case: dict[str, Any], repo_cache: Path, snapshots: Path) -> Path:
    repo = case["repository"]
    revisions = case["revisions"]
    repo_key = repo["repo_key"]
    commit = revisions["checkout_revision"]
    repo_dir = repo_cache / safe_slug(repo_key)
    snapshot = snapshots / f"{safe_slug(repo_key)}__{commit[:12]}"
    if snapshot.is_dir():
        return snapshot
    clone_or_fetch(repo["repo_url"], repo_dir)
    materialize_snapshot(repo_dir, commit, snapshot)
    return snapshot


def build_guideline(case: dict[str, Any]) -> str:
    classification = case.get("classification") or {}
    typ = classification.get("primary_hcvr_type") or "unknown"
    base = GUIDELINES.get(
        typ,
        "Audit whether the anchor participates in the vulnerability pattern "
        "described by the case metadata and whether a sensitive operation is "
        "reachable without the required security condition.",
    )
    vuln = case.get("vulnerability") or {}
    cwes = ", ".join(classification.get("cwe_ids") or [])
    description = vuln.get("description") or ""
    parts = [
        f"HCVR type: {typ}",
        f"Guideline: {base}",
    ]
    if cwes:
        parts.append(f"CWE: {cwes}")
    if description:
        parts.append(f"Case description: {description}")
    return "\n".join(parts)


def build_prompt(
    *,
    case: dict[str, Any],
    anchor: dict[str, Any],
    snapshot: Path,
    guideline: str,
) -> str:
    revisions = case["revisions"]
    vuln = case.get("vulnerability") or {}
    return f"""Audit the repository for the security risk described below.

Repository: {snapshot}
Exact commit: {revisions["checkout_revision"]}
Case: {case["identity_key"]}
Vulnerability ID: {vuln.get("id", "")}

Guideline:
{guideline}

Investigation anchor:
- Anchor ID: {anchor["anchor_id"]}
- File: {anchor["file"]}
- Lines: {anchor["start_line"]}-{anchor["end_line"]}
- Symbol: {anchor.get("symbol", "")}
- Span kind: {anchor.get("span_kind", "")}

Start at the anchor, read that source range, and inspect the smallest relevant
callers, callees, data flow, security checks, state transitions, and sensitive
effects needed to decide whether this anchor leads to the guideline risk. The
anchor is an investigation entry, not proof and not a boundary on repository
reading. Keep the audit bounded and finish in this single response. Prefer
focused line-range reads and search commands over printing entire large files.

Return a free-form audit report. Explain the relevant code path and why the risk
does or does not exist. Choose risk only when you can identify a concrete
sensitive operation reachable from this anchor and explain the missing,
incorrect, stale, confused, or unpropagated security condition. Otherwise choose
no-risk, using confidence to express remaining uncertainty.

For risk, cite exact file:line locations for the anchor relation, missing or
incorrect check, and sensitive effect. State the runtime conditions and values a
later PoC agent should observe or instrument to efficiently eliminate false
positives. Do not modify the repository, run tests, read patches, use historical
PoCs, or search external vulnerability information.

You must make a binary decision. End the report with exactly two machine-readable
lines. The Decision value must be either risk or no-risk. The Confidence value
must be a decimal from 0.00 to 1.00. Do not return unknown or any third decision.
"""


def run_case(
    *,
    codex: str,
    model: str,
    codex_home: Path,
    temp_root: Path,
    output: Path,
    case: dict[str, Any],
    anchor: dict[str, Any],
    snapshot: Path,
    timeout: int,
    max_attempts: int,
) -> dict[str, Any]:
    identity = case["identity_key"]
    slug = safe_slug(identity)
    reports_dir = output / "reports"
    report_path = reports_dir / f"{slug}.md"
    prompt_path = reports_dir / f"{slug}.prompt.txt"
    events_path = reports_dir / f"{slug}.events.jsonl"
    guideline = build_guideline(case)
    prompt = build_prompt(
        case=case,
        anchor=anchor,
        snapshot=snapshot,
        guideline=guideline,
    )
    prompt_path.write_text(prompt, encoding="utf-8")
    command = [
        codex,
        "exec",
        "--ignore-rules",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--cd",
        str(snapshot),
        "--model",
        model,
        "--output-last-message",
        str(report_path),
        "--json",
        "--color",
        "never",
        "-",
    ]
    environment = os.environ.copy()
    environment["CODEX_HOME"] = str(codex_home)
    environment["TMPDIR"] = str(temp_root)
    started = time.time()
    attempts: list[dict[str, Any]] = []
    state = "not_started"
    returncode: int | None = None
    decision: str | None = None
    confidence: float | None = None
    for attempt in range(1, max_attempts + 1):
        attempt_report = reports_dir / f"{slug}.attempt-{attempt:02d}.md"
        attempt_events = reports_dir / f"{slug}.attempt-{attempt:02d}.events.jsonl"
        attempt_command = command.copy()
        attempt_command[attempt_command.index(str(report_path))] = str(attempt_report)
        attempt_started = time.time()
        attempt_state = "completed"
        attempt_returncode: int | None = None
        attempt_returncode, output, attempt_state = run_command(
            attempt_command,
            cwd=snapshot,
            env=environment,
            input_text=prompt,
            timeout=timeout,
        )
        attempt_events.write_text(output, encoding="utf-8")
        if attempt_state == "completed" and attempt_returncode != 0:
            attempt_state = "codex_failed"

        report = attempt_report.read_text(encoding="utf-8") if attempt_report.is_file() else ""
        attempt_decision, attempt_confidence = parse_report(report)
        events = attempt_events.read_text(encoding="utf-8")
        if attempt_state == "completed" and not has_command_execution(events):
            attempt_state = "no_tool_execution"
        if attempt_state == "completed" and (
            attempt_decision is None or attempt_confidence is None
        ):
            attempt_state = "invalid_report_footer"
        attempts.append(
            {
                "attempt": attempt,
                "duration_seconds": round(time.time() - attempt_started, 3),
                "events": str(attempt_events),
                "report": str(attempt_report),
                "returncode": attempt_returncode,
                "state": attempt_state,
            }
        )
        state = attempt_state
        returncode = attempt_returncode
        shutil.copyfile(attempt_events, events_path)
        if attempt_report.is_file():
            shutil.copyfile(attempt_report, report_path)
        if attempt_state == "completed":
            decision = attempt_decision
            confidence = attempt_confidence
            break

    classification = case.get("classification") or {}
    return {
        "identity_key": identity,
        "case_id": case.get("new_unified_case_id"),
        "hcvr_type": classification.get("primary_hcvr_type"),
        "repo_url": case["repository"]["repo_url"],
        "checkout_revision": case["revisions"]["checkout_revision"],
        "anchor_id": anchor["anchor_id"],
        "file": anchor["file"],
        "start_line": anchor["start_line"],
        "end_line": anchor["end_line"],
        "state": state,
        "decision": decision,
        "confidence": confidence,
        "duration_seconds": round(time.time() - started, 3),
        "returncode": returncode,
        "attempt_count": len(attempts),
        "attempts": attempts,
        "report": str(report_path),
        "report_sha256": sha256_file(report_path) if report_path.is_file() else None,
        "prompt": str(prompt_path),
        "events": str(events_path),
    }


def write_prepare_packet(
    *,
    output: Path,
    case: dict[str, Any],
    anchor: dict[str, Any],
    snapshot: Path | None,
) -> dict[str, Any]:
    identity = case["identity_key"]
    slug = safe_slug(identity)
    reports_dir = output / "reports"
    prompt_path = reports_dir / f"{slug}.prompt.txt"
    guideline = build_guideline(case)
    prompt = build_prompt(
        case=case,
        anchor=anchor,
        snapshot=snapshot or Path("<snapshot-not-materialized-yet>"),
        guideline=guideline,
    )
    prompt_path.write_text(prompt, encoding="utf-8")
    classification = case.get("classification") or {}
    return {
        "identity_key": identity,
        "case_id": case.get("new_unified_case_id"),
        "hcvr_type": classification.get("primary_hcvr_type"),
        "repo_url": case["repository"]["repo_url"],
        "checkout_revision": case["revisions"]["checkout_revision"],
        "anchor_id": anchor["anchor_id"],
        "file": anchor["file"],
        "start_line": anchor["start_line"],
        "end_line": anchor["end_line"],
        "prompt": str(prompt_path),
        "snapshot": str(snapshot) if snapshot is not None else None,
        "state": "prepared",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--qa", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo-cache", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--codex-home", type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--skip", type=int, default=0)
    parser.add_argument("--anchor-index", type=int, default=0)
    parser.add_argument("--model", default="qwen3-coder:30b")
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--timeout", type=int, default=1200)
    parser.add_argument("--max-attempts", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--no-materialize", action="store_true")
    args = parser.parse_args()

    if args.limit < 1 or args.skip < 0 or args.anchor_index < 0:
        raise ValueError("limit must be positive; skip and anchor-index non-negative")
    if args.concurrency < 1 or args.max_attempts < 1:
        raise ValueError("concurrency and max-attempts must be positive")
    output = args.output_dir.resolve()
    if output.exists():
        raise FileExistsError(f"refusing existing audit output: {output}")
    codex = shutil.which(args.codex)
    if codex is None:
        raise FileNotFoundError(f"Codex executable not found: {args.codex}")
    codex_home = args.codex_home.resolve()
    if not codex_home.is_dir():
        raise FileNotFoundError(f"Codex home does not exist: {codex_home}")
    temp_root = args.temp_root.resolve()
    temp_root.mkdir(parents=True, exist_ok=True)
    repo_cache = args.repo_cache.resolve()
    snapshots = args.snapshot_root.resolve()
    repo_cache.mkdir(parents=True, exist_ok=True)
    snapshots.mkdir(parents=True, exist_ok=True)

    cases = load_selected_cases(args.qa.resolve(), args.limit, args.skip)
    output.mkdir(parents=True)
    (output / "reports").mkdir()
    selected_rows: list[dict[str, Any]] = []
    run_items: list[tuple[dict[str, Any], dict[str, Any], Path]] = []
    prepared_rows: list[dict[str, Any]] = []
    for case in cases:
        anchor = pick_anchor(case, args.anchor_index)
        snapshot = (
            None
            if args.no_materialize
            else ensure_snapshot(case, repo_cache, snapshots)
        )
        selected_rows.append(
            {
                "identity_key": case["identity_key"],
                "case_id": case.get("new_unified_case_id"),
                "repo_url": case["repository"]["repo_url"],
                "checkout_revision": case["revisions"]["checkout_revision"],
                "hcvr_type": (case.get("classification") or {}).get("primary_hcvr_type"),
                "anchor_id": anchor["anchor_id"],
                "file": anchor["file"],
                "start_line": anchor["start_line"],
                "end_line": anchor["end_line"],
                "snapshot": str(snapshot) if snapshot is not None else None,
            }
        )
        if args.prepare_only:
            prepared_rows.append(
                write_prepare_packet(
                    output=output,
                    case=case,
                    anchor=anchor,
                    snapshot=snapshot,
                )
            )
        else:
            if snapshot is None:
                raise ValueError("cannot run audits with --no-materialize")
            run_items.append((case, anchor, snapshot))
    write_jsonl(output / "selected_cases.jsonl", selected_rows)
    if args.prepare_only:
        write_jsonl(output / "audit_index.jsonl", prepared_rows)
        summary = {
            "schema_version": "hcvr_case_anchor_audit_run.v1",
            "qa": str(args.qa.resolve()),
            "limit": args.limit,
            "skip": args.skip,
            "anchor_index": args.anchor_index,
            "case_count": len(prepared_rows),
            "completed_count": 0,
            "risk_count": 0,
            "no_risk_count": 0,
            "failed_count": 0,
            "prepared_count": len(prepared_rows),
            "prepare_only": True,
            "snapshots_materialized": not args.no_materialize,
        }
        (output / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True), flush=True)
        return

    worker_args = {
        "codex": codex,
        "model": args.model,
        "codex_home": codex_home,
        "temp_root": temp_root,
        "output": output,
        "timeout": args.timeout,
        "max_attempts": args.max_attempts,
    }
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [
            pool.submit(run_case, case=case, anchor=anchor, snapshot=snapshot, **worker_args)
            for case, anchor, snapshot in run_items
        ]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print(json.dumps(result, ensure_ascii=False, sort_keys=True), flush=True)
    order = {case["identity_key"]: index for index, case in enumerate(cases)}
    results.sort(key=lambda row: order[row["identity_key"]])
    write_jsonl(output / "audit_index.jsonl", results)
    summary = {
        "schema_version": "hcvr_case_anchor_audit_run.v1",
        "qa": str(args.qa.resolve()),
        "model": args.model,
        "limit": args.limit,
        "skip": args.skip,
        "anchor_index": args.anchor_index,
        "case_count": len(results),
        "completed_count": sum(row["state"] == "completed" for row in results),
        "risk_count": sum(row["decision"] == "risk" for row in results),
        "no_risk_count": sum(row["decision"] == "no-risk" for row in results),
        "failed_count": sum(row["state"] != "completed" for row in results),
    }
    (output / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if summary["failed_count"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
