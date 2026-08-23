#!/usr/bin/env python3
"""Discover bounded initial Java build commands for exact-source IRIS cases.

This is the first-build companion to ``run_codeql_llm_repair_dispatch.py``.
It handles cases without an historical CodeQL failure receipt or command:

1. materialize a fresh copy from the receipt-bound source archive;
2. expose only build descriptors to the model;
3. validate a model-selected command against a small Maven/Gradle grammar;
4. run a bounded CodeQL database create; and
5. emit success/failure receipts compatible with the existing repair dispatcher.

No project-specific commands, source changes, repository overrides, package
installation, query changes, or pre-existing database reuse are permitted.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from route_hacker.runtime.bounded_process import run_bounded_process
from route_hacker.runtime.codeql_repair import (
    SAFE_BUILD_ARGS,
    compare_source_integrity,
    redact_text,
    source_integrity_snapshot,
    stable_json_sha256,
    valid_codeql_database,
    verify_exact_source,
)


SCHEMA_VERSION = "route_hacker_codeql_build_discovery.v1"
MODEL_OUTPUT_LIMIT = 16_000
SOURCE_SUCCESS_STATUSES = {
    "source_materialized_exact_archive_snapshot",
    "source_materialized_exact_clean_snapshot",
    "source_reused_exact_clean_snapshot",
}
MAVEN_GOALS = {"compile", "package", "verify"}
GRADLE_TASKS = {"classes", "assemble", "build"}
GRADLE_SAFE_ARGS = {"-x", "test"}
TOP_LEVEL_BUILD_FILES = (
    "pom.xml",
    "mvnw",
    "gradlew",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "build.xml",
)


class DiscoveryValidationError(ValueError):
    """Raised when discovery input or model output violates the contract."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def append_jsonl(path: Path, value: Mapping[str, Any], lock: threading.Lock) -> None:
    with lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            handle.write("\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise DiscoveryValidationError(f"{path}:{line_number} is not an object")
        values.append(value)
    return values


def source_receipts_by_case(rows: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            continue
        if row.get("status") not in SOURCE_SUCCESS_STATUSES:
            continue
        if case_id in indexed and stable_json_sha256(indexed[case_id]) != stable_json_sha256(row):
            raise DiscoveryValidationError(f"conflicting exact source receipts for {case_id}")
        indexed[case_id] = row
    return indexed


def _within(root: Path, candidate: Path) -> bool:
    return candidate == root or root in candidate.parents


def extract_source_archive(source_receipt: Mapping[str, Any], destination: Path) -> dict[str, Any]:
    archive_result = source_receipt.get("archive_result")
    archive = archive_result if isinstance(archive_result, Mapping) else {}
    archive_text = archive.get("archive_path")
    archive_sha256 = archive.get("archive_sha256")
    archive_url = archive.get("archive_url")
    if not isinstance(archive_text, str) or not isinstance(archive_sha256, str):
        raise DiscoveryValidationError("source receipt has no archive-bound source material")
    archive_path = Path(archive_text)
    if not archive_path.is_file() or sha256_file(archive_path) != archive_sha256:
        raise DiscoveryValidationError("source archive is absent or hash-mismatched")
    if destination.exists():
        raise DiscoveryValidationError("source extraction destination already exists")

    staging = destination.with_name(f".{destination.name}.extracting")
    if staging.exists():
        raise DiscoveryValidationError("source extraction staging directory already exists")
    staging.mkdir(parents=True)
    staging_root = staging.resolve()
    with tarfile.open(archive_path, "r:*") as archive_file:
        members = archive_file.getmembers()
        if not members:
            raise DiscoveryValidationError("source archive has no members")
        for member in members:
            target = (staging / member.name).resolve()
            if not _within(staging_root, target) or member.isdev():
                raise DiscoveryValidationError("source archive has an unsafe member")
            if member.issym() or member.islnk():
                link = Path(member.linkname)
                if link.is_absolute() or not _within(staging_root, (target.parent / link).resolve()):
                    raise DiscoveryValidationError("source archive has an unsafe link")
        archive_file.extractall(staging, members=members)
    entries = list(staging.iterdir())
    if len(entries) != 1 or not entries[0].is_dir():
        shutil.rmtree(staging, ignore_errors=True)
        raise DiscoveryValidationError("source archive must have one top-level directory")
    entries[0].replace(destination)
    staging.rmdir()
    return {
        "mode": "archive_verified_isolated_copy",
        "source_dir": str(destination.resolve()),
        "archive_path": str(archive_path.resolve()),
        "archive_sha256": archive_sha256,
        "archive_url": archive_url,
    }


def build_descriptor(source_dir: Path) -> dict[str, Any]:
    files = [name for name in TOP_LEVEL_BUILD_FILES if (source_dir / name).is_file()]
    previews: dict[str, str] = {}
    for name in ("pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"):
        path = source_dir / name
        if path.is_file():
            previews[name] = redact_text(path.read_text(encoding="utf-8", errors="replace")[:4000])
    return {
        "top_level_build_files": files,
        "has_maven_wrapper": (source_dir / "mvnw").is_file(),
        "has_gradle_wrapper": (source_dir / "gradlew").is_file(),
        "has_maven_pom": (source_dir / "pom.xml").is_file(),
        "has_gradle_build": (source_dir / "build.gradle").is_file()
        or (source_dir / "build.gradle.kts").is_file(),
        "descriptor_previews": previews,
    }


def build_prompt(
    *,
    case_id: str,
    project_slug: str,
    source_receipt: Mapping[str, Any],
    descriptor: Mapping[str, Any],
    approved_java_homes: list[str],
) -> str:
    return (
        "Choose the first bounded Java build command for an exact-source CodeQL database "
        "creation. You cannot execute tools, inspect files beyond the supplied descriptor, "
        "or request source/repository/query changes. Return JSON only.\n\n"
        f"Case: {case_id}\nProject: {project_slug}\n"
        f"Declared revision: {source_receipt.get('resolved_buggy_commit')}\n"
        f"Build descriptor: {json.dumps(descriptor, ensure_ascii=False, sort_keys=True)}\n\n"
        "Allowed output schema:\n"
        "{"
        "\"kind\":\"maven\"|\"gradle_wrapper\"|\"no_safe_command\","
        "\"java_home\":\"one approved Java home or null\","
        "\"goal\":\"compile\"|\"package\"|\"verify\" (Maven only),"
        "\"task\":\"classes\"|\"assemble\"|\"build\" (Gradle only),"
        "\"args\":[only safe args listed below],"
        "\"rationale\":\"short explanation\""
        "}\n"
        f"Approved Java homes: {json.dumps(approved_java_homes)}\n"
        f"Maven safe args: {json.dumps(sorted(SAFE_BUILD_ARGS))}\n"
        "Gradle safe args: [\"-x\", \"test\"] only, in that exact pair.\n"
        "Maven command always uses `mvn`; Gradle command always uses `bash ./gradlew`. "
        "Do not include shell syntax, paths, environment variables, repositories, downloads, "
        "or arbitrary arguments."
    )


def normalize_base_url(value: str) -> str:
    return value.strip().rstrip("/") + ("" if value.strip().rstrip("/").endswith("/v1") else "/v1")


def invoke_model(
    *,
    bridge_url: str,
    model: str,
    prompt: str,
    case_id: str,
    output_dir: Path,
    timeout_seconds: float,
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a bounded build-command discovery component. "
                    "Return only the requested JSON object. You have no tools."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0,
    }
    input_path = output_dir / "model-input.json"
    output_path = output_dir / "model-output.json"
    write_json(input_path, payload)
    request = urllib.request.Request(
        f"{normalize_base_url(bridge_url)}/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Iris-Run-Id": "compile-builder-v2-discovery",
            "X-Iris-Case-Id": case_id,
        },
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        raise DiscoveryValidationError(f"model transport failed: {type(error).__name__}: {error}") from error
    elapsed_seconds = round(time.monotonic() - started, 3)
    choices = result.get("choices") if isinstance(result, Mapping) else None
    message = choices[0].get("message") if isinstance(choices, list) and choices else None
    content = message.get("content") if isinstance(message, Mapping) else None
    if not isinstance(content, str) or not content.strip():
        raise DiscoveryValidationError("model returned no command decision")
    try:
        decision = json.loads(content)
    except json.JSONDecodeError as error:
        raise DiscoveryValidationError("model command decision is not JSON") from error
    if not isinstance(decision, dict):
        raise DiscoveryValidationError("model command decision is not an object")
    write_json(output_path, decision)
    return decision, {
        "model": model,
        "elapsed_seconds": elapsed_seconds,
        "input_path": str(input_path.resolve()),
        "input_sha256": sha256_file(input_path),
        "output_path": str(output_path.resolve()),
        "output_sha256": sha256_file(output_path),
        "provider_usage": result.get("usage") if isinstance(result, Mapping) else None,
    }


def validate_command_decision(
    decision: Mapping[str, Any],
    *,
    descriptor: Mapping[str, Any],
    approved_java_homes: list[str],
) -> tuple[list[str] | None, str | None]:
    kind = decision.get("kind")
    java_home = decision.get("java_home")
    if java_home is not None and java_home not in approved_java_homes:
        raise DiscoveryValidationError("model selected an unapproved Java home")
    if kind == "no_safe_command":
        return None, java_home
    args = decision.get("args", [])
    if not isinstance(args, list) or not all(isinstance(value, str) for value in args):
        raise DiscoveryValidationError("model args must be a string list")
    if kind == "maven":
        if not descriptor.get("has_maven_pom"):
            raise DiscoveryValidationError("Maven decision requires a top-level pom.xml")
        goal = decision.get("goal")
        if goal not in MAVEN_GOALS:
            raise DiscoveryValidationError("model selected an invalid Maven lifecycle goal")
        if any(arg not in SAFE_BUILD_ARGS for arg in args):
            raise DiscoveryValidationError("Maven decision contains an unsafe argument")
        return ["mvn", *args, str(goal)], java_home
    if kind == "gradle_wrapper":
        if not descriptor.get("has_gradle_wrapper"):
            raise DiscoveryValidationError("Gradle decision requires a gradlew wrapper")
        task = decision.get("task")
        if task not in GRADLE_TASKS:
            raise DiscoveryValidationError("model selected an invalid Gradle task")
        if args not in ([], ["-x", "test"]):
            raise DiscoveryValidationError("Gradle decision contains an unsafe argument")
        return ["bash", "./gradlew", str(task), *args], java_home
    raise DiscoveryValidationError("model selected an unsupported build kind")


def source_receipt_for_attempt(
    source_receipt: Mapping[str, Any],
    source_dir: Path,
) -> dict[str, Any]:
    result = dict(source_receipt)
    result["source_dir"] = str(source_dir.resolve())
    return result


def codeql_command(codeql: Path, database: Path, source_dir: Path, build_command: list[str]) -> list[str]:
    return [
        str(codeql),
        "database",
        "create",
        str(database),
        "--language=java",
        f"--source-root={source_dir}",
        "--overwrite",
        "--command",
        shlex.join(build_command),
    ]


def run_case(
    *,
    case: Mapping[str, Any],
    source_receipt: Mapping[str, Any],
    output_dir: Path,
    codeql: Path,
    bridge_url: str,
    model: str,
    approved_java_homes: list[str],
    timeout_seconds: float,
    inactivity_timeout_seconds: float,
    model_timeout_seconds: float,
    dry_run: bool,
) -> dict[str, Any]:
    case_id = str(case["case_id"])
    case_dir = output_dir / "cases" / re.sub(r"[^A-Za-z0-9._-]+", "_", case_id)
    case_dir.mkdir(parents=True, exist_ok=False)
    try:
        materialization = extract_source_archive(source_receipt, case_dir / "source")
        attempt_source_receipt = source_receipt_for_attempt(source_receipt, case_dir / "source")
        expected_revision = str(
            source_receipt.get("resolved_buggy_commit")
            or source_receipt.get("declared_buggy_commit")
            or ""
        )
        evidence = verify_exact_source(
            case_dir / "source",
            expected_revision,
            attempt_source_receipt,
            expected_case_id=case_id,
        )
        if not evidence.get("verified"):
            return {
                "schema_version": SCHEMA_VERSION,
                "case_id": case_id,
                "project_slug": case.get("project_slug"),
                "status": "source_revision_verification_failed",
                "source_revision_evidence": evidence,
                "recorded_at": utc_now(),
            }
        descriptor = build_descriptor(case_dir / "source")
        prompt = build_prompt(
            case_id=case_id,
            project_slug=str(case.get("project_slug") or ""),
            source_receipt=source_receipt,
            descriptor=descriptor,
            approved_java_homes=approved_java_homes,
        )
        (case_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
        if dry_run:
            return {
                "schema_version": SCHEMA_VERSION,
                "case_id": case_id,
                "project_slug": case.get("project_slug"),
                "status": "build_command_discovery_dry_run",
                "descriptor": descriptor,
                "source_materialization": materialization,
                "source_revision_evidence": evidence,
                "recorded_at": utc_now(),
            }
        decision, model_receipt = invoke_model(
            bridge_url=bridge_url,
            model=model,
            prompt=prompt,
            case_id=case_id,
            output_dir=case_dir,
            timeout_seconds=model_timeout_seconds,
        )
        build_command, java_home = validate_command_decision(
            decision,
            descriptor=descriptor,
            approved_java_homes=approved_java_homes,
        )
        if build_command is None:
            return {
                "schema_version": SCHEMA_VERSION,
                "case_id": case_id,
                "project_slug": case.get("project_slug"),
                "status": "no_safe_initial_build_command",
                "decision": decision,
                "model_invocation": model_receipt,
                "descriptor": descriptor,
                "source_materialization": materialization,
                "source_revision_evidence": evidence,
                "recorded_at": utc_now(),
            }
        database_dir = case_dir / "codeql-db"
        command = codeql_command(codeql, database_dir, case_dir / "source", build_command)
        log_path = case_dir / "codeql-build.log"
        before = source_integrity_snapshot(case_dir / "source")
        environment = dict(os.environ)
        if java_home:
            environment["JAVA_HOME"] = java_home
            environment["PATH"] = f"{Path(java_home) / 'bin'}:{environment.get('PATH', '')}"
        with log_path.open("w", encoding="utf-8") as handle:
            handle.write("$ " + shlex.join(command) + "\n")
            handle.flush()
            bounded = run_bounded_process(
                command,
                cwd=case_dir / "source",
                env=environment,
                timeout_seconds=timeout_seconds,
                inactivity_timeout_seconds=inactivity_timeout_seconds,
                term_grace_seconds=min(30, max(1, timeout_seconds / 20)),
                progress_path=log_path,
                stdout=handle,
                stderr=handle,
                text=True,
            )
        integrity = compare_source_integrity(before, source_integrity_snapshot(case_dir / "source"))
        database_valid = valid_codeql_database(database_dir)
        status = (
            "codeql_db_discovered"
            if bounded.returncode == 0 and database_valid and integrity.get("verified")
            else "codeql_db_failed"
        )
        return {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "project_slug": case.get("project_slug"),
            "status": status,
            "recorded_at": utc_now(),
            "decision": decision,
            "model_invocation": model_receipt,
            "descriptor": descriptor,
            "source_materialization": materialization,
            "source_revision_evidence": evidence,
            "source_integrity_evidence": integrity,
            "source_dir": str((case_dir / "source").resolve()),
            "resolved_buggy_commit": expected_revision,
            "planned_codeql_database_command": command,
            "codeql_database_dir": str(database_dir.resolve()),
            "codeql_database_create_result": {
                **bounded.to_dict(),
                "log_path": str(log_path.resolve()),
                "log_sha256": sha256_file(log_path),
            },
            "database_valid": database_valid,
        }
    except (DiscoveryValidationError, OSError, ValueError) as error:
        return {
            "schema_version": SCHEMA_VERSION,
            "case_id": case_id,
            "project_slug": case.get("project_slug"),
            "status": "build_command_discovery_failed",
            "recorded_at": utc_now(),
            "error_type": type(error).__name__,
            "error": str(error),
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case-manifest", type=Path, required=True)
    parser.add_argument("--source-receipts", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--codeql", type=Path, required=True)
    parser.add_argument("--openai-bridge-url", required=True)
    parser.add_argument("--openai-model", default="DeepSeek-V4-Pro")
    parser.add_argument("--approved-java-home", action="append", default=[])
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--case-id-file", type=Path)
    parser.add_argument("--model-timeout-seconds", type=float, default=900)
    parser.add_argument("--codeql-timeout-seconds", type=float, default=7200)
    parser.add_argument("--codeql-inactivity-timeout-seconds", type=float, default=1800)
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.workers < 1 or args.model_timeout_seconds <= 0 or args.codeql_timeout_seconds <= 0:
        raise SystemExit("workers and timeouts must be positive")
    if args.output_dir.exists():
        raise SystemExit(f"refusing to overwrite output directory: {args.output_dir}")
    if not args.case_manifest.is_file() or not args.source_receipts.is_file() or not args.codeql.is_file():
        raise SystemExit("case manifest, source receipts, and CodeQL binary must exist")
    if args.case_id_file and not args.case_id_file.is_file():
        raise SystemExit("case ID file must exist")

    sources = source_receipts_by_case(read_jsonl(args.source_receipts))
    cases = read_jsonl(args.case_manifest)
    selected_ids = (
        {
            value.strip()
            for value in args.case_id_file.read_text(encoding="utf-8").splitlines()
            if value.strip()
        }
        if args.case_id_file
        else None
    )
    cases = [
        row
        for row in cases
        if isinstance(row.get("case_id"), str)
        and (selected_ids is None or row["case_id"] in selected_ids)
    ]
    if args.limit is not None:
        cases = cases[: args.limit]
    args.output_dir.mkdir(parents=True)
    ledger = args.output_dir / "build_discovery_receipts.jsonl"
    lock = threading.Lock()
    results: list[dict[str, Any]] = []

    def submit(case: dict[str, Any]) -> dict[str, Any]:
        case_id = str(case["case_id"])
        source = sources.get(case_id)
        if source is None:
            result = {
                "schema_version": SCHEMA_VERSION,
                "case_id": case_id,
                "project_slug": case.get("project_slug"),
                "status": "source_receipt_missing",
                "recorded_at": utc_now(),
            }
        else:
            result = run_case(
                case=case,
                source_receipt=source,
                output_dir=args.output_dir,
                codeql=args.codeql,
                bridge_url=args.openai_bridge_url,
                model=args.openai_model,
                approved_java_homes=args.approved_java_home,
                timeout_seconds=args.codeql_timeout_seconds,
                inactivity_timeout_seconds=args.codeql_inactivity_timeout_seconds,
                model_timeout_seconds=args.model_timeout_seconds,
                dry_run=args.dry_run,
            )
        append_jsonl(ledger, result, lock)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(submit, case) for case in cases]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())

    failed_for_repair = sorted(
        (row for row in results if row["status"] == "codeql_db_failed"),
        key=lambda row: str(row["case_id"]),
    )
    repair_sources = [
        sources[row["case_id"]]
        for row in failed_for_repair
        if row["case_id"] in sources
    ]
    repair_ledger = [
        {
            "schema_version": "route_hacker_codeql_repair_dispatch.v1:case_completion",
            "case_id": row["case_id"],
            "status": "no_safe_deterministic_repair",
            "failed_receipt_sha256": stable_json_sha256(row),
            "source_receipt_sha256": stable_json_sha256(sources[row["case_id"]]),
            "input_binding": {
                "producer": SCHEMA_VERSION,
                "discovery_receipt_sha256": stable_json_sha256(row),
                "exact_source_receipt_sha256": stable_json_sha256(sources[row["case_id"]]),
            },
        }
        for row in failed_for_repair
        if row["case_id"] in sources
    ]
    write_jsonl(args.output_dir / "repair_failed_receipts.jsonl", failed_for_repair)
    write_jsonl(args.output_dir / "repair_source_receipts.jsonl", repair_sources)
    write_jsonl(args.output_dir / "repair_prior_ledger.jsonl", repair_ledger)
    write_json(
        args.output_dir / "summary.json",
        {
            "schema_version": SCHEMA_VERSION,
            "status": "completed",
            "created_at": utc_now(),
            "counts": {
                "selected_cases": len(cases),
                "statuses": dict(sorted(Counter(str(row["status"]) for row in results).items())),
                "failed_cases_exported_for_repair": len(failed_for_repair),
            },
            "contract": {
                "completed_projection_cases_not_selected_by_caller": True,
                "source_edits_forbidden": True,
                "revision_substitution_forbidden": True,
                "repository_or_mirror_injection_forbidden": True,
                "arbitrary_shell_commands_forbidden": True,
                "model_command_schema_locally_validated": True,
                "failed_first_builds_are_dispatcher_inputs": True,
            },
            "repair_dispatch_inputs": {
                "failed_receipts": str(
                    (args.output_dir / "repair_failed_receipts.jsonl").resolve()
                ),
                "source_receipts": str(
                    (args.output_dir / "repair_source_receipts.jsonl").resolve()
                ),
                "prior_ledger": str(
                    (args.output_dir / "repair_prior_ledger.jsonl").resolve()
                ),
            },
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
