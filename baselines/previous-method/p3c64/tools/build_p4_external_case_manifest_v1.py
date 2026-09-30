#!/usr/bin/env python3
"""Build a frozen P4 external-case manifest from provenance-recovered cases.

This builder does not inspect or score candidate code.  It converts only
``source_commit_recovered`` rows from the v2 provenance ledger into the
minimal case/anchor manifest required by the separate generic candidate-pool
builder.  The resulting anchors are offline evaluation mappings, not runtime
retrieval inputs or vulnerability proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "p4_external_case_manifest_v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$", flags=re.IGNORECASE)


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def normalize_text(value: Any) -> str:
    return str(value or "").strip()


def core_labels(labels: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        label
        for label in labels
        if label.get("core_metric_eligible") is True
        and normalize_text(label.get("metric_inclusion")) == "core_positive"
        and normalize_text(label.get("candidate_pool_status")) == "covered"
        and bool(label.get("candidate_refs"))
        and (
            label.get("source_contract_valid") is True
            or label.get("strict_source_contract") is True
            or label.get("candidate_closure_verified") is True
        )
    ]


def snapshot_root(label: dict[str, Any]) -> Path:
    source_path = Path(normalize_text(label.get("source_snapshot_path")))
    rel_file = Path(normalize_text(label.get("file")))
    if not source_path.is_file() or not rel_file.parts:
        raise ValueError(
            f"label has unusable source snapshot mapping: {label.get('label_id')}"
        )
    root = source_path
    for _ in rel_file.parts:
        root = root.parent
    if (root / rel_file).resolve() != source_path.resolve():
        raise ValueError(
            f"label snapshot path does not end in label file: {label.get('label_id')}"
        )
    return root


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provenance-ledger", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    paths = {
        "provenance_ledger": args.provenance_ledger.resolve(),
        "canonical_cases": args.cases.resolve(),
        "canonical_labels": args.labels.resolve(),
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"missing P4 external-case input(s): {missing}")
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite P4 case manifest: {output_dir}")

    cases_by_id = {
        normalize_text(case.get("case_id")): case
        for case in read_jsonl(paths["canonical_cases"])
    }
    labels_by_case: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for label in read_jsonl(paths["canonical_labels"]):
        labels_by_case[normalize_text(label.get("case_id"))].append(label)
    recovered_rows = [
        row
        for row in read_jsonl(paths["provenance_ledger"])
        if normalize_text(row.get("provenance_status")) == "source_commit_recovered"
    ]
    if not recovered_rows:
        raise ValueError("provenance ledger contains no source_commit_recovered rows")

    manifest_rows: list[dict[str, Any]] = []
    source_audit_rows: list[dict[str, Any]] = []
    track_counts: Counter[str] = Counter()
    language_counts: Counter[str] = Counter()
    for recovery in sorted(recovered_rows, key=lambda row: normalize_text(row.get("case_id"))):
        case_id = normalize_text(recovery.get("case_id"))
        case = cases_by_id.get(case_id)
        if case is None:
            raise ValueError(f"recovered case absent from canonical cases: {case_id}")
        labels = core_labels(labels_by_case[case_id])
        if not labels:
            raise ValueError(f"recovered case has no core source-backed labels: {case_id}")

        roots = {snapshot_root(label) for label in labels}
        if len(roots) != 1:
            raise ValueError(
                f"recovered case has non-uniform snapshot roots: {case_id}: {roots}"
            )
        repo_path = next(iter(roots)).resolve()
        if not repo_path.is_dir():
            raise FileNotFoundError(f"recovered repo snapshot is missing: {repo_path}")

        anchors: list[dict[str, Any]] = []
        label_source_audit: list[dict[str, Any]] = []
        for label in sorted(labels, key=lambda row: normalize_text(row.get("label_id"))):
            source_hash = normalize_text(label.get("source_snapshot_sha256"))
            source_path = Path(normalize_text(label.get("source_snapshot_path")))
            if not SHA256_RE.fullmatch(source_hash):
                raise ValueError(f"invalid source snapshot hash: {label.get('label_id')}")
            if sha256_file(source_path) != source_hash:
                raise ValueError(
                    f"source snapshot hash mismatch: {label.get('label_id')} {source_path}"
                )
            anchors.append(
                {
                    "file": normalize_text(label.get("file")),
                    "function": normalize_text(label.get("symbol")),
                    "start_line": int(label.get("start_line") or 0),
                    "end_line": int(label.get("end_line") or 0),
                    "anchor_source": normalize_text(label.get("label_id")),
                }
            )
            label_source_audit.append(
                {
                    "label_id": label.get("label_id"),
                    "source_snapshot_path": str(source_path),
                    "source_snapshot_sha256": source_hash,
                    "file": label.get("file"),
                    "start_line": int(label.get("start_line") or 0),
                    "end_line": int(label.get("end_line") or 0),
                }
            )

        track_id = normalize_text(case.get("track_id"))
        row = {
            "case_id": case.get("case_id"),
            "cve_id": case.get("cve_id"),
            "repo_key": case.get("repo_key"),
            "repo_path": str(repo_path),
            "evidence_level": "source_commit_recovered_core_positive",
            "subtype": track_id,
            "track_id": track_id,
            "track_display_name": case.get("track_display_name"),
            "language": case.get("language"),
            "project_group": case.get("project_group"),
            "source_advisory_id": case.get("cve_id") or case.get("ghsa_id"),
            "pre_patch_commit": recovery.get("recovered_pre_patch_commit"),
            "fix_commit": recovery.get("recovered_fix_commit"),
            "source_archive_path": recovery.get("source_archive_path"),
            "positive_anchors": anchors,
            "offline_label_contract": {
                "anchor_role": "evaluation_mapping_only",
                "core_source_contract_label_count": len(labels),
                "non_anchor_semantics": "unknown_unlabeled_background_not_safe_negative",
                "not_vulnerability_proof": True,
            },
        }
        manifest_rows.append(row)
        source_audit_rows.append(
            {
                "case_id": case.get("case_id"),
                "repo_key": case.get("repo_key"),
                "repo_path": str(repo_path),
                "pre_patch_commit": recovery.get("recovered_pre_patch_commit"),
                "fix_commit": recovery.get("recovered_fix_commit"),
                "source_archive_path": recovery.get("source_archive_path"),
                "core_label_source_audit": label_source_audit,
                "provenance_ledger_status": recovery.get("provenance_status"),
            }
        )
        track_counts.update([track_id])
        language_counts.update([normalize_text(case.get("language"))])

    if len({row["case_id"] for row in manifest_rows}) != len(manifest_rows):
        raise ValueError("duplicate recovered case IDs")
    if len({row["repo_key"] for row in manifest_rows}) != len(manifest_rows):
        raise ValueError("duplicate recovered repo keys")

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "external_cases.v1.jsonl", manifest_rows)
    write_jsonl(output_dir / "source_snapshot_audit.v1.jsonl", source_audit_rows)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen_case_manifest_no_retrieval",
        "created_at": now_utc(),
        "inputs": {
            key: {"path": str(path), "sha256": sha256_file(path)}
            for key, path in paths.items()
        },
        "case_count": len(manifest_rows),
        "repo_count": len({row["repo_key"] for row in manifest_rows}),
        "project_family_count": len(
            {
                re.sub(r"__[0-9a-f]{8,64}$", "", normalize_text(row["repo_key"]))
                for row in manifest_rows
            }
        ),
        "track_case_counts": dict(sorted(track_counts.items())),
        "language_case_counts": dict(sorted(language_counts.items())),
        "boundary": (
            "This manifest freezes only provenance-recovered external case metadata "
            "and offline anchor mappings. It does not contain a full-repository "
            "candidate pool, embedding, score, rank, model fit, or retrieval result."
        ),
    }
    write_json(output_dir / "summary.json", summary)
    manifest = {"artifact": output_dir.name, "files": {}}
    for path in sorted(output_dir.iterdir()):
        if path.is_file():
            manifest["files"][path.name] = {
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
    write_json(output_dir / "manifest.v1.json", manifest)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
