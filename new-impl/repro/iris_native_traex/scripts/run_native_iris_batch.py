#!/usr/bin/env python3
"""Create resumable receipts for bounded native-IRIS case dispatch."""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")
        handle.flush()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)


def input_path_errors(row: dict[str, Any]) -> list[str]:
    inputs = row.get("input_paths")
    if not isinstance(inputs, dict):
        return ["input_paths is not an object"]
    errors = []
    for key, kind in (("source", "dir"), ("codeql_db", "dir"), ("package_names", "file")):
        value = inputs.get(key)
        if not value:
            errors.append(f"input_paths.{key} is missing")
            continue
        path = Path(str(value))
        if kind == "dir" and not path.is_dir():
            errors.append(f"input_paths.{key} is not an existing directory: {path}")
        if kind == "file" and not path.is_file():
            errors.append(f"input_paths.{key} is not an existing file: {path}")
    return errors


def codeql_database_errors(row: dict[str, Any]) -> list[str]:
    """Reject interrupted CodeQL creation directories before consuming LLM budget."""

    inputs = row.get("input_paths")
    if not isinstance(inputs, dict) or not inputs.get("codeql_db"):
        return []
    database = Path(str(inputs["codeql_db"]))
    if not database.is_dir():
        return []
    errors = []
    if not (database / "codeql-database.yml").is_file():
        errors.append(f"input_paths.codeql_db is missing codeql-database.yml: {database}")
    if not (database / "db-java").is_dir():
        errors.append(
            "input_paths.codeql_db is missing db-java; likely an interrupted CodeQL database creation: "
            f"{database}"
        )
    return errors


def validate_iris_manifest(
    rows: list[dict[str, Any]],
    allowlist_rows: list[dict[str, Any]],
    expected_count: int,
) -> list[dict[str, Any]]:
    """Validate the frozen evaluation boundary before admitting any work."""

    if len(rows) != expected_count:
        raise ValueError(
            f"IRIS manifest must contain exactly {expected_count} rows; found {len(rows)}"
        )
    allowlist = {str(row.get("identity_key")) for row in allowlist_rows if row.get("identity_key")}
    seen: set[str] = set()
    required = ("identity_key", "project_slug", "iris_query", "input_paths")
    for index, row in enumerate(rows, start=1):
        missing = [key for key in required if not row.get(key)]
        if missing:
            raise ValueError(f"manifest row {index} missing: {', '.join(missing)}")
        identity = str(row["identity_key"])
        if identity in seen:
            raise ValueError(f"duplicate manifest identity_key: {identity}")
        seen.add(identity)
        if identity not in allowlist:
            raise ValueError(f"manifest identity is outside the 143-case allowlist: {identity}")
        inputs = row["input_paths"]
        if not isinstance(inputs, dict):
            raise ValueError(f"manifest row {index} input_paths must be an object")
        input_missing = [key for key in ("source", "codeql_db", "package_names") if not inputs.get(key)]
        if input_missing:
            raise ValueError(
                f"manifest row {index} input_paths missing: {', '.join(input_missing)}"
            )
        revisions = row.get("revisions")
        if not isinstance(revisions, dict) or not revisions.get("v2_checkout_revision"):
            raise ValueError(f"manifest row {index} must record revisions.v2_checkout_revision")
        if not row.get("source_evidence") and not row.get("source_provenance"):
            raise ValueError(f"manifest row {index} must record source_evidence or source_provenance")
        if not isinstance(row.get("input_status"), dict):
            raise ValueError(f"manifest row {index} must record input_status")
    return rows


def latest_attempt_rows(rows: list[dict[str, Any]], attempt_id: str) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for row in rows:
        if str(row.get("attempt_id")) != attempt_id or not row.get("identity_key"):
            continue
        latest[str(row["identity_key"])] = row
    return latest


def summarize_receipts(path: Path) -> dict[str, Any]:
    rows = read_jsonl(path) if path.is_file() else []
    statuses = collections.Counter(str(row.get("status")) for row in rows)
    verified = [row for row in rows if row.get("status") == "completed_verified"]
    numeric_fields = (
        "candidate_apis",
        "labelled_sources",
        "labelled_taint_propagators",
        "labelled_sinks",
        "vanilla_paths",
        "posthoc_paths",
        "vanilla_tp_paths_method",
        "posthoc_tp_paths_method",
    )
    totals = {
        field: sum(
            value for row in verified
            if isinstance((value := (row.get("iris_statistics") or {}).get(field)), (int, float))
        )
        for field in numeric_fields
    }
    totals["elapsed_seconds"] = sum(
        value for row in verified if isinstance((value := row.get("elapsed_seconds")), (int, float))
    )
    return {
        "schema_version": "iris_native_traex_batch_summary.v1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "receipt_count": len(rows),
        "status_counts": dict(sorted(statuses.items())),
        "completed_verified_count": len(verified),
        "verified_totals": totals,
    }


def single_case_command(
    *,
    python: str,
    runner: Path,
    workspace: Path,
    run_id: str,
    bridge_url: str,
    llm: str,
    num_threads: int,
    label_api_batch_size: int,
    label_func_param_batch_size: int,
    timeout_seconds: int,
    output_dir: Path,
) -> list[str]:
    """Build the exact native-IRIS runner command recorded by a batch attempt."""

    return [
        python,
        str(runner),
        "--workspace",
        str(workspace),
        "--run-id",
        run_id,
        "--bridge-url",
        bridge_url,
        "--llm",
        llm,
        "--num-threads",
        str(num_threads),
        "--label-api-batch-size",
        str(label_api_batch_size),
        "--label-func-param-batch-size",
        str(label_func_param_batch_size),
        "--timeout-seconds",
        str(timeout_seconds),
        "--output-dir",
        str(output_dir),
    ]


def validate_codeql_bundle(
    *,
    python: str,
    materializer: Path,
    clean_iris_root: Path,
    codeql_dir: Path,
) -> dict[str, Any]:
    """Check the shared official Action bundle once before any case is queued."""

    command = [
        python,
        str(materializer),
        "--validate-codeql-bundle",
        "--clean-iris-root",
        str(clean_iris_root),
        "--codeql-dir",
        str(codeql_dir),
    ]
    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise RuntimeError(f"cannot start CodeQL bundle preflight: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[-2000:]
        raise RuntimeError(
            "CodeQL Action bundle preflight failed before queue creation "
            f"(exit {completed.returncode}): {detail}"
        )
    try:
        bundle = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "CodeQL Action bundle preflight returned non-JSON output: "
            f"{completed.stdout[-500:]}"
        ) from exc
    if not isinstance(bundle, dict):
        raise RuntimeError("CodeQL Action bundle preflight returned a non-object payload")
    return bundle


def workspace_lock_path(workspace: Path) -> Path:
    """Return the sibling lock path used to prevent duplicate case execution."""

    return workspace.parent / f".{workspace.name}.lock"


def quarantine_workspace(workspace: Path) -> Path:
    """Preserve an interrupted materialization before a resume retry replaces it."""

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = workspace.with_name(f"{workspace.name}.interrupted-{timestamp}")
    suffix = 1
    while destination.exists():
        destination = workspace.with_name(
            f"{workspace.name}.interrupted-{timestamp}-{suffix}"
        )
        suffix += 1
    shutil.move(str(workspace), str(destination))
    return destination


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iris-manifest", type=Path, required=True)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--expected-manifest-count", type=int, default=45)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--clean-iris-root", type=Path, required=True)
    parser.add_argument("--codeql-dir", type=Path, required=True)
    parser.add_argument("--bridge-url", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--materializer", type=Path, required=True)
    parser.add_argument("--single-case-runner", type=Path, required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--max-workers", type=int, default=2)
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "skip verified receipts and retry other cases; an unlocked interrupted "
            "workspace is preserved under a timestamped sibling name before rematerialization"
        ),
    )
    parser.add_argument("--attempt-id", default="attempt-1")
    parser.add_argument("--llm", choices=("gpt-traex-flash", "gpt-traex-pro"), default="gpt-traex-flash")
    parser.add_argument("--num-threads", type=int, default=1)
    parser.add_argument("--label-api-batch-size", type=int, default=30)
    parser.add_argument("--label-func-param-batch-size", type=int, default=20)
    parser.add_argument(
        "--bridge-max-concurrency",
        type=int,
        default=8,
        help="maximum simultaneous bridge completions; prevents remote requests queueing past client timeouts",
    )
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    if args.max_workers < 1 or args.max_workers > 8:
        raise SystemExit("--max-workers must be in [1, 8]")
    if args.num_threads < 1:
        raise SystemExit("--num-threads must be positive")
    if args.label_api_batch_size < 1:
        raise SystemExit("--label-api-batch-size must be positive")
    if args.label_func_param_batch_size < 1:
        raise SystemExit("--label-func-param-batch-size must be positive")
    if args.bridge_max_concurrency < 1:
        raise SystemExit("--bridge-max-concurrency must be positive")
    max_inflight_llm_requests = args.max_workers * args.num_threads
    if max_inflight_llm_requests > args.bridge_max_concurrency:
        raise SystemExit(
            "max-workers * num-threads exceeds bridge capacity "
            f"({args.max_workers} * {args.num_threads} > {args.bridge_max_concurrency}); "
            "reduce project or per-project IRIS concurrency to prevent queued requests timing out"
        )
    if not safe_name(args.attempt_id) or safe_name(args.attempt_id) != args.attempt_id:
        raise SystemExit("--attempt-id may contain only letters, numbers, '.', '_' and '-'")

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger = output_dir / "receipts.jsonl"
    queue_path = output_dir / "queue.jsonl"
    manifest_path = args.iris_manifest.resolve()
    allowlist_path = args.allowlist.resolve()
    manifest_rows = validate_iris_manifest(
        read_jsonl(manifest_path),
        read_jsonl(allowlist_path),
        args.expected_manifest_count,
    )
    bundle = validate_codeql_bundle(
        python=args.python,
        materializer=args.materializer.resolve(),
        clean_iris_root=args.clean_iris_root.resolve(),
        codeql_dir=args.codeql_dir.resolve(),
    )
    manifest_hash = sha256_path(manifest_path)
    queue_rows = [
        {
            **row,
            "case_id": row.get("case_id") or row["identity_key"],
            "dispatch_state": "queued",
            "attempt_id": args.attempt_id,
        }
        for row in manifest_rows
    ]
    if queue_path.exists():
        existing_queue = read_jsonl(queue_path)
        existing_hash = sha256_path(queue_path)
        expected_queue = "".join(json.dumps(row, sort_keys=True) + "\n" for row in queue_rows)
        expected_hash = hashlib.sha256(expected_queue.encode("utf-8")).hexdigest()
        if existing_hash != expected_hash:
            raise SystemExit(
                "queue.jsonl does not match the supplied IRIS manifest; "
                "use a new output directory or restore the original manifest"
            )
        queue_rows = existing_queue
    else:
        with queue_path.open("w", encoding="utf-8") as handle:
            for row in queue_rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    (output_dir / "codeql-bundle-preflight.json").write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    completed: set[str] = set()
    if args.resume and ledger.is_file():
        completed = {
            str(row["identity_key"])
            for row in read_jsonl(ledger)
            if str(row.get("attempt_id")) == args.attempt_id
            and row.get("status") == "completed_verified"
            and row.get("identity_key")
        }
    selected = [row for row in queue_rows if str(row["identity_key"]) not in completed]
    if args.limit is not None:
        selected = selected[: args.limit]

    def run_case(row: dict[str, Any]) -> dict[str, Any]:
        slug = str(row["project_slug"])
        identity_key = str(row["identity_key"])
        case_id = str(row.get("case_id") or identity_key)
        case_dir = output_dir / "cases" / safe_name(case_id)
        workspace = args.workspace_root.resolve() / args.attempt_id / safe_name(case_id)
        run_id = f"native-traex-{args.attempt_id}-{safe_name(slug)}"
        base_receipt = {
            "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "case_id": case_id,
            "identity_key": identity_key,
            "project_slug": slug,
            "attempt_id": args.attempt_id,
            "manifest_sha256": manifest_hash,
            "allowlist_sha256": sha256_path(allowlist_path),
            "input_paths": row.get("input_paths"),
            "input_status": row.get("input_status"),
            "revisions": row.get("revisions"),
            "run_id": run_id,
            "workspace": str(workspace),
            "output_dir": str(case_dir),
        }
        path_errors = input_path_errors(row) + codeql_database_errors(row)
        if path_errors:
            return {
                **base_receipt,
                "status": "input_unavailable",
                "retryable": True,
                "error_kind": "input_path_validation",
                "errors": path_errors,
            }
        lock_path = workspace_lock_path(workspace)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return {
                **base_receipt,
                "status": "workspace_busy",
                "retryable": True,
                "error_kind": "workspace_lock_exists",
                "workspace_lock": str(lock_path),
            }
        try:
            with os.fdopen(lock_fd, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "attempt_id": args.attempt_id,
                            "case_id": case_id,
                            "identity_key": identity_key,
                            "pid": os.getpid(),
                            "started_at": datetime.now(timezone.utc).replace(
                                microsecond=0
                            ).isoformat(),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
            quarantined_workspace = None
            if workspace.exists() and args.resume:
                quarantined_workspace = quarantine_workspace(workspace)
            materialize = [
                args.python, str(args.materializer), "--manifest", str(manifest_path),
                "--case-id", case_id, "--clean-iris-root", str(args.clean_iris_root),
                "--codeql-dir", str(args.codeql_dir), "--workspace", str(workspace),
            ]
            try:
                materialized = subprocess.run(materialize, text=True, capture_output=True, check=False)
            except OSError as exc:
                return {
                    **base_receipt,
                    "status": "materialization_failed",
                    "retryable": True,
                    "error_kind": "materializer_spawn",
                    "error": str(exc),
                }
            if materialized.returncode != 0:
                return {
                    **base_receipt,
                    "status": "materialization_failed",
                    "retryable": True,
                    "error_kind": "materializer_exit",
                    "runner_returncode": materialized.returncode,
                    "stderr": materialized.stderr[-2000:],
                    "stdout": materialized.stdout[-2000:],
                    "quarantined_workspace": (
                        str(quarantined_workspace) if quarantined_workspace else None
                    ),
                }
            run = single_case_command(
                python=args.python,
                runner=args.single_case_runner,
                workspace=workspace,
                run_id=run_id,
                bridge_url=args.bridge_url,
                llm=args.llm,
                num_threads=args.num_threads,
                label_api_batch_size=args.label_api_batch_size,
                label_func_param_batch_size=args.label_func_param_batch_size,
                timeout_seconds=args.timeout_seconds,
                output_dir=case_dir,
            )
            try:
                executed = subprocess.run(run, text=True, capture_output=True, check=False)
            except OSError as exc:
                return {
                    **base_receipt,
                    "status": "runner_failed",
                    "retryable": True,
                    "error_kind": "runner_spawn",
                    "error": str(exc),
                }
            summary_path = case_dir / "summary.json"
            try:
                summary = json.loads(summary_path.read_text()) if summary_path.is_file() else {}
            except (OSError, json.JSONDecodeError) as exc:
                summary = {}
                summary_error = str(exc)
            else:
                summary_error = None
            return {
                **base_receipt,
                "status": summary.get("status", "runner_summary_missing"),
                "runner_returncode": executed.returncode,
                "retryable": summary.get("status") != "completed_verified",
                "summary_path": str(summary_path) if summary_path.is_file() else None,
                "summary_error": summary_error,
                "verified_completion": summary.get("verified_completion"),
                "elapsed_seconds": summary.get("elapsed_seconds"),
                "iris_statistics": summary.get("iris_statistics") or {},
                "label_response_audit": {
                    "total_dispatched_prompt_count": (summary.get("label_response_audit") or {}).get("total_dispatched_prompt_count"),
                    "all_valid": (summary.get("label_response_audit") or {}).get("all_valid"),
                },
                "artifact_gate": summary.get("artifact_gate") or {},
                "quarantined_workspace": (
                    str(quarantined_workspace) if quarantined_workspace else None
                ),
            }
        finally:
            lock_path.unlink(missing_ok=True)

    with ThreadPoolExecutor(max_workers=args.max_workers) as pool:
        futures = [pool.submit(run_case, row) for row in selected]
        for future in as_completed(futures):
            try:
                receipt = future.result()
            except Exception as exc:  # Keep one malformed case from stopping the queue.
                receipt = {
                    "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                    "attempt_id": args.attempt_id,
                    "status": "dispatcher_case_exception",
                    "retryable": True,
                    "error_kind": "worker_exception",
                    "error": repr(exc),
                }
            append_jsonl(ledger, receipt)
            (output_dir / "summary.json").write_text(
                json.dumps(summarize_receipts(ledger), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(json.dumps(receipt, sort_keys=True), flush=True)
    (output_dir / "summary.json").write_text(
        json.dumps(summarize_receipts(ledger), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
