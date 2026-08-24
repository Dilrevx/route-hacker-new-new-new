#!/usr/bin/env python3
"""Audit guideline release coverage over a fixed HCVR identity set."""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def read_records(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() != ".json":
        return read_jsonl(path)
    payload = read_json(path)
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("cases", "items", "rows", "records"):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def format_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ";".join(str(item) for item in value)
    return str(value).replace("\n", " ").replace("\r", " ")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else []
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: format_cell(row.get(field)) for field in fields})


def load_identities(path: Path) -> list[str]:
    identities: list[str] = []
    if path.suffix.lower() == ".json":
        payload = read_json(path)
        if isinstance(payload, dict):
            for key in ("identities", "identity_keys", "selected_identities", "paper_eval_identities"):
                value = payload.get(key)
                if isinstance(value, list):
                    identities.extend(str(item).strip() for item in value if str(item).strip())
                    break
            if not identities and isinstance(payload.get("added_identities"), list):
                added = [str(value).strip() for value in payload["added_identities"] if str(value).strip()]
                expected_count = payload.get("unique_identity_count") or payload.get("case_count")
                if expected_count is not None and int(expected_count) != len(added):
                    sibling_allowlist = path.parent / "hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl"
                    if sibling_allowlist.exists():
                        return load_identities(sibling_allowlist)
                    raise ValueError(
                        f"{path} contains only {len(added)} added_identities but declares {expected_count} identities; "
                        "pass the full identity allowlist JSONL instead"
                    )
                identities.extend(added)
        if not identities:
            for row in read_records(path):
                identity = str(row.get("identity_key") or "").strip()
                if identity:
                    identities.append(identity)
    else:
        for row in read_jsonl(path):
            identity = str(row.get("identity_key") or "").strip()
            if identity:
                identities.append(identity)
    if not identities:
        raise ValueError(f"identity file has no identity_key rows: {path}")
    duplicates = [key for key, count in Counter(identities).items() if count > 1]
    if duplicates:
        raise ValueError(f"duplicate identities in {path}: {duplicates[:10]}")
    return identities


def load_cases(path: Path) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    for row in read_records(path):
        identity = str(row.get("identity_key") or "").strip()
        if identity:
            cases[identity] = row
    return cases


def load_records_by_id(path: Path | None, id_field: str = "cve_id") -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in read_jsonl(path):
        key = str(row.get(id_field) or "").strip()
        if key:
            out[key] = row
    return out


def load_cluster_members(path: Path | None) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    if path is None:
        return {}, set()
    payload = read_json(path)
    by_member: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cluster in payload.get("clusters") or []:
        cluster_id = cluster.get("cluster_id")
        cluster_name = cluster.get("cluster_name")
        for member in cluster.get("members") or []:
            by_member[str(member)].append(
                {
                    "cluster_id": cluster_id,
                    "cluster_name": cluster_name,
                    "source_kind": "cluster",
                }
            )
        for sub_pattern in cluster.get("sub_patterns") or []:
            sub_name = sub_pattern.get("name") or cluster_name
            for member in sub_pattern.get("members") or []:
                by_member[str(member)].append(
                    {
                        "cluster_id": cluster_id,
                        "cluster_name": cluster_name,
                        "sub_pattern_name": sub_name,
                        "source_kind": "sub_pattern",
                    }
                )
    return by_member, {str(member) for member in payload.get("noise") or [] if str(member)}


def direct_guideline_text(row: dict[str, Any]) -> str:
    for key in ("retrieval_guideline", "guideline_text", "guideline"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def load_sidecar(path: Path) -> dict[str, dict[str, Any]]:
    by_identity: dict[str, dict[str, Any]] = {}
    rows = read_jsonl(path) if path.suffix.lower() != ".json" else normalize_json_sidecar(read_json(path))
    for row in rows:
        identity = str(row.get("identity_key") or row.get("case_id") or row.get("new_unified_case_id") or "").strip()
        if not identity:
            continue
        by_identity[identity] = {
            "identity_key": identity,
            "guideline_text": direct_guideline_text(row),
            "guideline_ids": row.get("guideline_ids") or [],
            "mechanism_ids": row.get("mechanism_ids") or [],
            "mechanism_names": row.get("mechanism_names") or [],
            "cve_ids": row.get("cve_ids") or [],
        }
    return by_identity


def normalize_json_sidecar(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and "guidelines" in payload:
        payload = payload["guidelines"]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        rows: list[dict[str, Any]] = []
        for key, value in payload.items():
            if isinstance(value, str):
                rows.append({"identity_key": key, "guideline_text": value})
            elif isinstance(value, dict):
                row = dict(value)
                row.setdefault("identity_key", key)
                rows.append(row)
        return rows
    return []


def load_review_queue(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    if path is None or not path.exists():
        return {}
    by_member: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(path):
        for cve_id in row.get("cve_ids") or []:
            by_member[str(cve_id)].append(row)
    return by_member


def vulnerability_ids(case: dict[str, Any], identity_key: str) -> list[str]:
    vuln = case.get("vulnerability") or {}
    values = [vuln.get("id"), *(vuln.get("aliases") or [])]
    if "::" in identity_key:
        values.append(identity_key.split("::", 1)[1])
    out: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if item and item not in out:
            out.append(item)
    return out


def coverage_category(row: dict[str, Any], primary_sidecar: str) -> str:
    if row.get(f"covered_{primary_sidecar}"):
        return "covered_by_primary_sidecar"
    if not row["cve_ids"]:
        return "ghsa_or_non_cve_no_cvelist_join"
    if not row["in_raw"] and not row["in_structured"]:
        return "missing_from_cve_clustering_raw_structured"
    if not row["in_refined_cluster"]:
        return "present_in_raw_but_cluster_noise"
    if row["in_review_queue"]:
        return "clustered_but_review_only_release_gate"
    if row["in_mechanism_candidates"]:
        return "candidate_exists_but_no_sidecar"
    return "clustered_but_no_candidate_or_join_gap"


def audit_coverage(
    *,
    identities: list[str],
    cases: dict[str, dict[str, Any]],
    raw_records: dict[str, dict[str, Any]],
    structured_records: dict[str, dict[str, Any]],
    cluster_members: dict[str, list[dict[str, Any]]],
    cluster_noise: set[str],
    candidate_members: set[str],
    review_queue: dict[str, list[dict[str, Any]]],
    sidecars: dict[str, dict[str, dict[str, Any]]],
    primary_sidecar: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    missing_cases: list[str] = []
    for identity in identities:
        case = cases.get(identity)
        if case is None:
            missing_cases.append(identity)
            case = {"identity_key": identity}
        vuln_ids = vulnerability_ids(case, identity)
        cve_ids = [value for value in vuln_ids if CVE_RE.match(value)]
        classification = case.get("classification") or {}
        classification_sources = sorted(
            {
                str(source.get("source_family") or "")
                for source in classification.get("classification_sources") or []
                if isinstance(source, dict) and source.get("source_family")
            }
        )
        present_raw = sorted(value for value in vuln_ids if value in raw_records)
        present_structured = sorted(value for value in vuln_ids if value in structured_records)
        present_cluster = sorted(value for value in vuln_ids if value in cluster_members)
        present_noise = sorted(value for value in vuln_ids if value in cluster_noise)
        present_candidates = sorted(value for value in vuln_ids if value in candidate_members)
        present_review = sorted(value for value in vuln_ids if value in review_queue)
        blockers = sorted(
            {
                str(blocker)
                for cve_id in present_review
                for item in review_queue.get(cve_id, [])
                for blocker in (item.get("release_status") or {}).get("blockers") or []
            }
        )
        row = {
            "identity_key": identity,
            "case_id": case.get("new_unified_case_id") or "",
            "vuln_ids": vuln_ids,
            "cve_ids": cve_ids,
            "primary_hcvr_type": classification.get("primary_hcvr_type") or "",
            "hcvr_types": classification.get("hcvr_types") or [],
            "dataset_cwe_ids": classification.get("cwe_ids") or [],
            "classification_sources": classification_sources,
            "raw_cwe_ids": sorted({str(raw_records[cve_id].get("cwe_id")) for cve_id in present_raw if raw_records[cve_id].get("cwe_id")}),
            "structured_cwe_ids": sorted(
                {
                    str(cwe)
                    for cve_id in present_structured
                    for cwe in structured_records[cve_id].get("cwe_chain") or []
                    if cwe
                }
            ),
            "in_raw": bool(present_raw),
            "in_structured": bool(present_structured),
            "in_refined_cluster": bool(present_cluster),
            "in_cluster_noise": bool(present_noise),
            "in_mechanism_candidates": bool(present_candidates),
            "in_review_queue": bool(present_review),
            "review_blockers": blockers,
        }
        for name, sidecar in sidecars.items():
            row[f"covered_{name}"] = identity in sidecar
            if identity in sidecar:
                row[f"{name}_mechanism_ids"] = sidecar[identity].get("mechanism_ids") or []
        row["coverage_category"] = coverage_category(row, primary_sidecar)
        rows.append(row)

    summary = build_summary(
        rows,
        missing_cases=missing_cases,
        sidecar_names=sorted(sidecars),
        primary_sidecar=primary_sidecar,
        raw_records=raw_records,
        structured_records=structured_records,
        cluster_noise=cluster_noise,
    )
    return summary, rows


def count_true(rows: list[dict[str, Any]], field: str) -> int:
    return sum(1 for row in rows if row.get(field))


def counter_dict(counter: Counter[Any]) -> dict[str, int]:
    return {str(key): value for key, value in counter.most_common()}


def build_summary(
    rows: list[dict[str, Any]],
    *,
    missing_cases: list[str],
    sidecar_names: list[str],
    primary_sidecar: str,
    raw_records: dict[str, dict[str, Any]],
    structured_records: dict[str, dict[str, Any]],
    cluster_noise: set[str],
) -> dict[str, Any]:
    total = len(rows)
    coverage_by_sidecar = {name: count_true(rows, f"covered_{name}") for name in sidecar_names}
    category_counts = Counter(row["coverage_category"] for row in rows)
    raw_or_structured_count = sum(1 for row in rows if row["in_raw"] or row["in_structured"])
    return {
        "schema_version": "hcvr_guideline_coverage_audit.v1",
        "identity_count": total,
        "missing_case_count": len(missing_cases),
        "missing_case_sample": missing_cases[:20],
        "primary_sidecar": primary_sidecar,
        "coverage_by_sidecar": coverage_by_sidecar,
        "source_presence": {
            "has_cve_like_id": sum(1 for row in rows if row["cve_ids"]),
            "in_raw": count_true(rows, "in_raw"),
            "in_structured": count_true(rows, "in_structured"),
            "in_refined_cluster": count_true(rows, "in_refined_cluster"),
            "in_cluster_noise": count_true(rows, "in_cluster_noise"),
            "in_mechanism_candidates": count_true(rows, "in_mechanism_candidates"),
            "in_review_queue": count_true(rows, "in_review_queue"),
        },
        "metadata_presence": {
            "dataset_cwe_present": sum(1 for row in rows if row["dataset_cwe_ids"]),
            "raw_cwe_present": sum(1 for row in rows if row["raw_cwe_ids"]),
            "structured_cwe_present": sum(1 for row in rows if row["structured_cwe_ids"]),
        },
        "coverage_category_counts": counter_dict(category_counts),
        "coverage_upper_bounds": {
            "current_primary_sidecar": coverage_by_sidecar.get(primary_sidecar, 0),
            "if_review_queue_released_for_current_candidates": count_true(rows, "in_mechanism_candidates"),
            "if_noise_singletons_released_from_current_raw_structured": raw_or_structured_count,
            "if_all_cve_ids_ingested": sum(1 for row in rows if row["cve_ids"]),
            "if_cve_and_ghsa_supported": total,
        },
        "missing_primary_by_hcvr_type": counter_dict(
            Counter(row["primary_hcvr_type"] or "(empty)" for row in rows if not row.get(f"covered_{primary_sidecar}"))
        ),
        "category_by_hcvr_type": {
            category: counter_dict(
                Counter(row["primary_hcvr_type"] or "(empty)" for row in rows if row["coverage_category"] == category)
            )
            for category in sorted(category_counts)
        },
        "input_stats": {
            "raw_record_count": len(raw_records),
            "raw_cwe_missing_count": sum(1 for row in raw_records.values() if not row.get("cwe_id")),
            "structured_record_count": len(structured_records),
            "structured_cwe_missing_count": sum(1 for row in structured_records.values() if not row.get("cwe_chain")),
            "cluster_noise_count": len(cluster_noise),
        },
    }


def load_candidate_members(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    members: set[str] = set()
    for row in read_jsonl(path):
        members.update(str(member) for member in row.get("members") or [] if str(member))
    return members


def parse_sidecar_args(values: list[str]) -> dict[str, Path]:
    out: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ValueError(f"--sidecar must be label=path, got: {value}")
        label, raw_path = value.split("=", 1)
        label = label.strip()
        if not label:
            raise ValueError(f"--sidecar label is empty: {value}")
        out[label] = Path(raw_path)
    return out


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Guideline Coverage Audit",
        "",
        "This report audits whether a fixed HCVR identity set is reachable by the offline guideline construction artifacts.",
        "It separates corpus intake, clustering, release gating, and sidecar coverage so recall misses are not misattributed to embedding quality.",
        "",
        "## Summary",
        "",
        f"- Identities: {summary['identity_count']}",
        f"- Primary sidecar: `{summary['primary_sidecar']}`",
        f"- Current primary sidecar coverage: {summary['coverage_upper_bounds']['current_primary_sidecar']}/{summary['identity_count']}",
        f"- Current candidate upper bound: {summary['coverage_upper_bounds']['if_review_queue_released_for_current_candidates']}/{summary['identity_count']}",
        f"- Current raw/structured upper bound with noise singleton handling: {summary['coverage_upper_bounds']['if_noise_singletons_released_from_current_raw_structured']}/{summary['identity_count']}",
        f"- CVE-id upper bound after intake repair: {summary['coverage_upper_bounds']['if_all_cve_ids_ingested']}/{summary['identity_count']}",
        f"- CVE+GHSA upper bound after alias-source repair: {summary['coverage_upper_bounds']['if_cve_and_ghsa_supported']}/{summary['identity_count']}",
        "",
        "## Sidecar Coverage",
        "",
        "| Sidecar | Covered |",
        "| --- | ---: |",
    ]
    for name, count in summary["coverage_by_sidecar"].items():
        lines.append(f"| `{name}` | {count}/{summary['identity_count']} |")
    lines.extend(
        [
            "",
            "## Coverage Categories",
            "",
            "| Category | Count |",
            "| --- | ---: |",
        ]
    )
    for category, count in summary["coverage_category_counts"].items():
        lines.append(f"| `{category}` | {count} |")
    inputs = summary.get("inputs") or {}
    if inputs:
        lines.extend(
            [
                "",
                "## Inputs",
                "",
                "| Input | Path |",
                "| --- | --- |",
            ]
        )
        for name, value in inputs.items():
            if isinstance(value, dict):
                for label, path_value in sorted(value.items()):
                    lines.append(f"| `{name}.{label}` | `{path_value}` |")
            else:
                lines.append(f"| `{name}` | `{value}` |")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `missing_from_cve_clustering_raw_structured` means the case never entered the offline CVE clustering corpus.",
            "- `present_in_raw_but_cluster_noise` means the case entered raw/structured CVE data but HDBSCAN did not assign it to a cluster.",
            "- `clustered_but_review_only_release_gate` means the case has a candidate guideline but release policy kept it out of the recall sidecar.",
            "- `ghsa_or_non_cve_no_cvelist_join` means the current CVEList-oriented join cannot connect the advisory identity.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identities", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--raw-cves", type=Path)
    parser.add_argument("--structured-cves", type=Path)
    parser.add_argument("--clusters", type=Path)
    parser.add_argument("--mechanism-candidates", type=Path)
    parser.add_argument("--review-queue", type=Path)
    parser.add_argument("--sidecar", action="append", default=[], help="label=path. May be repeated.")
    parser.add_argument("--primary-sidecar", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    sidecar_paths = parse_sidecar_args(args.sidecar)
    if args.primary_sidecar not in sidecar_paths:
        raise ValueError(f"--primary-sidecar {args.primary_sidecar!r} is not one of: {sorted(sidecar_paths)}")
    cluster_members, cluster_noise = load_cluster_members(args.clusters)
    summary, rows = audit_coverage(
        identities=load_identities(args.identities),
        cases=load_cases(args.cases),
        raw_records=load_records_by_id(args.raw_cves),
        structured_records=load_records_by_id(args.structured_cves),
        cluster_members=cluster_members,
        cluster_noise=cluster_noise,
        candidate_members=load_candidate_members(args.mechanism_candidates),
        review_queue=load_review_queue(args.review_queue),
        sidecars={label: load_sidecar(path) for label, path in sidecar_paths.items()},
        primary_sidecar=args.primary_sidecar,
    )
    summary["inputs"] = {
        "identities": str(args.identities),
        "cases": str(args.cases),
        "raw_cves": str(args.raw_cves) if args.raw_cves else "",
        "structured_cves": str(args.structured_cves) if args.structured_cves else "",
        "clusters": str(args.clusters) if args.clusters else "",
        "mechanism_candidates": str(args.mechanism_candidates) if args.mechanism_candidates else "",
        "review_queue": str(args.review_queue) if args.review_queue else "",
        "sidecars": {label: str(path) for label, path in sorted(sidecar_paths.items())},
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "case_coverage.jsonl", rows)
    write_csv(args.output_dir / "case_coverage.csv", rows)
    write_markdown(args.output_dir / "README.md", summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
