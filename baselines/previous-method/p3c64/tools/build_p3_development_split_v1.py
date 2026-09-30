#!/usr/bin/env python3
"""Freeze a nested project-family P3 development split without retrieval.

P3 is a new method experiment.  It uses only the M7 strict ``inner_train``
portion as development material, then separates it again by project family:
one deterministic family bucket is selection-only and the remainder is
fitting-only.  M8 is read only to audit direct recorded identity overlap; its
candidate rankings, query vectors, and results are never read.
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


SCHEMA_VERSION = "p3_nested_development_split_v1"
# The deterministic seed was selected before P3 training/retrieval as the
# first candidate from a fixed enumeration that keeps every runtime track on
# both project-family-disjoint sides. It uses no retrieval/vector/result data.
SPLIT_SEED = "p3-hard-competition-query-adapter-v1-stratified-5"
SPLIT_MODULUS = 4
SELECTION_BUCKET = 0


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def normalized_project_family(repo_key: str) -> str:
    return re.sub(r"__[0-9a-f]{8,64}$", "", repo_key, flags=re.IGNORECASE)


def selection_bucket(project_family: str) -> int:
    value = f"{SPLIT_SEED}\0{project_family}".encode("utf-8")
    return int(hashlib.sha256(value).hexdigest()[:16], 16) % SPLIT_MODULUS


def identities(row: dict[str, Any]) -> set[str]:
    values = {
        str(row.get("case_id") or "").strip().lower(),
        str(row.get("cve_id") or "").strip().lower(),
        str(row.get("ghsa_id") or "").strip().lower(),
        str(row.get("repo_key") or "").strip().lower(),
        str(row.get("project_group") or "").strip().lower(),
    }
    return {value for value in values if value}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--proposal", type=Path, required=True)
    parser.add_argument("--training-pairs", type=Path, required=True)
    parser.add_argument("--m8-selected-cases", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    proposal_path = args.proposal.resolve()
    pairs_path = args.training_pairs.resolve()
    m8_cases_path = args.m8_selected_cases.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite P3 split output: {output_dir}")
    for path in (proposal_path, pairs_path, m8_cases_path):
        if not path.is_file():
            raise FileNotFoundError(path)

    proposal_rows = read_jsonl(proposal_path)
    pairs = read_jsonl(pairs_path)
    m8_cases = read_jsonl(m8_cases_path)
    pair_case_ids = {str(pair["case_id"]) for pair in pairs}
    proposal_by_case = {str(row["case_id"]): row for row in proposal_rows}
    if len(proposal_by_case) != len(proposal_rows):
        raise ValueError("proposal has duplicate case IDs")
    if not pair_case_ids <= set(proposal_by_case):
        raise ValueError("training pairs reference cases absent from proposal")

    eligible = [
        row
        for row in proposal_rows
        if str(row.get("inner_split") or "") == "inner_train"
        and str(row["case_id"]) in pair_case_ids
    ]
    if len(eligible) != 155:
        raise ValueError(f"expected 155 pair-backed M7 inner-train cases, found {len(eligible)}")
    if {str(row["case_id"]) for row in eligible} != pair_case_ids:
        raise ValueError("pair-backed M7 inner-train cases differ from pair manifest")

    case_split: dict[str, str] = {}
    split_rows: list[dict[str, Any]] = []
    family_to_split: dict[str, str] = {}
    for row in eligible:
        copy = dict(row)
        family = normalized_project_family(str(copy["repo_key"]))
        split = "p3_selection" if selection_bucket(family) == SELECTION_BUCKET else "p3_fitting"
        existing = family_to_split.setdefault(family, split)
        if existing != split:
            raise ValueError(f"project family split conflict: {family}")
        copy.update(
            {
                "p3_split": split,
                "p3_project_family": family,
                "p3_split_seed": SPLIT_SEED,
                "p3_split_modulus": SPLIT_MODULUS,
                "p3_selection_bucket": SELECTION_BUCKET,
            }
        )
        case_id = str(copy["case_id"])
        if case_id in case_split:
            raise ValueError(f"duplicate P3 case ID: {case_id}")
        case_split[case_id] = split
        split_rows.append(copy)

    counts = Counter(row["p3_split"] for row in split_rows)
    expected_counts = {"p3_fitting": 112, "p3_selection": 43}
    if dict(sorted(counts.items())) != expected_counts:
        raise ValueError(f"unexpected P3 split counts: {dict(counts)}")
    if not {row["p3_split"] for row in split_rows} == set(expected_counts):
        raise ValueError("P3 split has an empty side")
    selection_tracks = Counter(
        str(row["track_id"]) for row in split_rows if row["p3_split"] == "p3_selection"
    )
    fitting_tracks = Counter(
        str(row["track_id"]) for row in split_rows if row["p3_split"] == "p3_fitting"
    )
    if len(selection_tracks) != 10 or len(fitting_tracks) != 10:
        raise ValueError(
            "P3 development split does not retain all ten runtime tracks on both sides"
        )

    split_pairs: list[dict[str, Any]] = []
    pair_split_counts: Counter[str] = Counter()
    for pair in pairs:
        copy = dict(pair)
        case_id = str(copy["case_id"])
        split = case_split.get(case_id)
        if split is None:
            raise ValueError(f"pair does not map to P3 eligible case: {copy['pair_id']}")
        family = normalized_project_family(str(copy["repo_key"]))
        if family_to_split.get(family) != split:
            raise ValueError(f"pair project family maps to a different P3 split: {copy['pair_id']}")
        copy["p3_split"] = split
        copy["p3_project_family"] = family
        split_pairs.append(copy)
        pair_split_counts[split] += 1
    if dict(sorted(pair_split_counts.items())) != {"p3_fitting": 217, "p3_selection": 78}:
        raise ValueError(f"unexpected P3 pair split counts: {dict(pair_split_counts)}")

    m8_identity_values = {
        value
        for row in m8_cases
        for value in identities(row)
    }
    direct_identity_overlaps: list[dict[str, Any]] = []
    for row in split_rows:
        matched = sorted(identities(row) & m8_identity_values)
        if matched:
            direct_identity_overlaps.append({"case_id": row["case_id"], "matches": matched})
    if direct_identity_overlaps:
        raise ValueError(f"P3 development material overlaps M8 recorded identities: {direct_identity_overlaps[:5]}")

    output_dir.mkdir(parents=True, exist_ok=False)
    split_rows.sort(key=lambda row: str(row["case_id"]))
    split_pairs.sort(key=lambda row: str(row["pair_id"]))
    write_jsonl(output_dir / "p3_development_cases.v1.jsonl", split_rows)
    write_jsonl(output_dir / "p3_development_pairs.v1.jsonl", split_pairs)
    isolation = {
        "schema_version": "p3_m8_recorded_identity_isolation_v1",
        "status": "passed",
        "m8_selected_case_count": len(m8_cases),
        "p3_development_case_count": len(split_rows),
        "direct_recorded_identity_overlap_count": len(direct_identity_overlaps),
        "direct_recorded_identity_overlaps": direct_identity_overlaps,
        "boundary": (
            "Audit compares recorded case/CVE/GHSA/repository/project-group strings only. "
            "It does not claim semantic independence beyond those identities and reads no M8 "
            "query, candidate, score, rank, or result artifact."
        ),
    }
    write_json(output_dir / "m8_recorded_identity_isolation.v1.json", isolation)
    summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "frozen_pre_training_pre_retrieval",
        "created_at_utc": now_utc(),
        "inputs": {
            "proposal": {"path": str(proposal_path), "sha256": sha256_file(proposal_path)},
            "training_pairs": {"path": str(pairs_path), "sha256": sha256_file(pairs_path)},
            "m8_selected_cases": {"path": str(m8_cases_path), "sha256": sha256_file(m8_cases_path)},
        },
        "split_rule": {
            "unit": "normalized project family",
            "algorithm": "sha256(seed + NUL + normalized_project_family) modulo modulus",
            "seed": SPLIT_SEED,
            "modulus": SPLIT_MODULUS,
            "selection_bucket": SELECTION_BUCKET,
            "fitting_bucket_rule": "all buckets other than selection_bucket",
            "seed_selection": (
                "Before training/retrieval, use the first seed in the deterministic "
                "suffix enumeration that retains all runtime tracks on both sides "
                "with 30-55 selection cases. No embedding, ranking, or result data "
                "was read during seed selection."
            ),
        },
        "counts": {
            "eligible_case_count": len(split_rows),
            "eligible_project_family_count": len(family_to_split),
            "case_count_by_split": dict(sorted(counts.items())),
            "pair_count": len(split_pairs),
            "pair_count_by_split": dict(sorted(pair_split_counts.items())),
            "selection_track_case_counts": dict(sorted(selection_tracks.items())),
            "fitting_track_case_counts": dict(sorted(fitting_tracks.items())),
        },
        "hard_constraints": {
            "uses_only_m7_inner_train_pair_backed_cases": True,
            "m7_inner_val_rows_excluded": True,
            "p3_project_families_are_disjoint": True,
            "all_runtime_tracks_present_on_both_p3_sides": True,
            "m8_read_only_identity_audit_only": True,
            "m8_query_candidate_score_rank_or_result_read": False,
            "training_or_retrieval_performed": False,
            "source_anchor_semantics_unchanged": True,
            "non_anchor_candidates_remain_unlabeled_background": True,
        },
        "next_gate": (
            "Freeze a finite P3 hard-competition query-adapter method contract before "
            "training. Selection may inspect only p3_selection; M7 inner_val and M8 remain "
            "unavailable to P3 model selection."
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
    print(
        json.dumps(
            {
                "status": summary["status"],
                "case_count_by_split": summary["counts"]["case_count_by_split"],
                "pair_count_by_split": summary["counts"]["pair_count_by_split"],
                "m8_identity_isolation": isolation["status"],
                "training_or_retrieval": "not_run",
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
