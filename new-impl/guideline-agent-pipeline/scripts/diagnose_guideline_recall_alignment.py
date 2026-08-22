#!/usr/bin/env python3
"""Join guideline-group diagnostics with same-identity recall ranks."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


DEFAULT_BUDGETS = (30, 50, 100, 150, 200, 300, 500)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\t".join(fields) + "\n")
        for row in rows:
            handle.write("\t".join(format_tsv(row.get(field)) for field in fields) + "\n")


def format_tsv(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value) or "n/a"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).replace("\t", " ").replace("\n", " ") or "n/a"


def parse_budgets(text: str) -> list[int]:
    values = sorted({int(item.strip()) for item in text.split(",") if item.strip()})
    if not values or any(value < 1 for value in values):
        raise ValueError("budgets must be positive integers")
    return values


def normalize_rank(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit():
        parsed = int(value)
        return parsed if parsed > 0 else None
    return None


def best_rank(row: dict[str, Any]) -> int | None:
    for key in ("best_known_anchor_rank", "rank"):
        rank = normalize_rank(row.get(key))
        if rank is not None:
            return rank
    anchor_ranks = [
        normalize_rank(anchor.get("rank"))
        for anchor in row.get("top_anchors", [])
        if isinstance(anchor, dict) and anchor.get("known_anchor_overlap")
    ]
    anchor_ranks = [rank for rank in anchor_ranks if rank is not None]
    return min(anchor_ranks) if anchor_ranks else None


def hit(rank: int | None, budget: int) -> bool:
    return rank is not None and rank <= budget


def index_by_identity(rows: list[dict[str, Any]], label: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    duplicates: list[str] = []
    for row in rows:
        identity = row.get("identity_key")
        if not isinstance(identity, str) or not identity:
            raise ValueError(f"{label} row missing identity_key: {row}")
        if identity in indexed:
            duplicates.append(identity)
            continue
        indexed[identity] = row
    if duplicates:
        raise ValueError(f"{label} has duplicate identities: {sorted(duplicates)[:10]}")
    return indexed


def group_clean_enough(group: dict[str, Any], min_purity: float) -> bool:
    flags = set(group.get("flags") or [])
    blocking_flags = {"pending_review", "mixed_hcvr", "mixed_cwe", "incomplete_actionability_fields"}
    if flags & blocking_flags:
        return False
    purity = group.get("primary_hcvr_purity")
    if isinstance(purity, (int, float)) and purity < min_purity:
        return False
    return True


def load_assignments(path: Path) -> dict[str, list[dict[str, Any]]]:
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(path):
        guideline_id = str(row.get("guideline_id") or "")
        if guideline_id:
            by_group[guideline_id].append(row)
    return by_group


def diagnose(
    *,
    group_rows: list[dict[str, Any]],
    assignments: dict[str, list[dict[str, Any]]],
    recall_rows: list[dict[str, Any]],
    recall_label: str,
    baseline_rows: list[dict[str, Any]] | None,
    baseline_label: str | None,
    budgets: list[int],
    primary_budget: int,
    min_purity: float,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    recall = index_by_identity(recall_rows, recall_label)
    baseline = index_by_identity(baseline_rows, baseline_label or "baseline") if baseline_rows else None
    recall_set = set(recall)
    baseline_set = set(baseline or {})
    same_identity_baseline = baseline is None or recall_set == baseline_set

    case_rows: list[dict[str, Any]] = []
    group_diagnostics: list[dict[str, Any]] = []
    assigned_identities: set[str] = set()
    recall_joined_identities: set[str] = set()
    baseline_joined_identities: set[str] = set()

    for group in group_rows:
        guideline_id = str(group.get("guideline_id") or "")
        group_assignments = assignments.get(guideline_id, [])
        identities = sorted({str(row.get("identity_key") or "") for row in group_assignments if row.get("identity_key")})
        assigned_identities.update(identities)
        ranks = []
        baseline_ranks = []
        for identity in identities:
            recall_row = recall.get(identity)
            baseline_row = baseline.get(identity) if baseline else None
            rank = best_rank(recall_row) if recall_row else None
            baseline_rank = best_rank(baseline_row) if baseline_row else None
            if recall_row:
                recall_joined_identities.add(identity)
            if baseline_row:
                baseline_joined_identities.add(identity)
            ranks.append(rank)
            baseline_ranks.append(baseline_rank)
            case_rows.append(
                {
                    "identity_key": identity,
                    "guideline_id": guideline_id,
                    "guideline_group_key": group.get("guideline_group_key"),
                    "mechanism_id": group.get("mechanism_id"),
                    "mechanism_name": group.get("mechanism_name"),
                    "mechanism_family": group.get("mechanism_family"),
                    "primary_hcvr_type": next(
                        (row.get("primary_hcvr_type") for row in group_assignments if row.get("identity_key") == identity),
                        "",
                    ),
                    "recall_label": recall_label,
                    "rank": rank,
                    "hit_at_primary_budget": hit(rank, primary_budget),
                    "baseline_label": baseline_label,
                    "baseline_rank": baseline_rank,
                    "baseline_hit_at_primary_budget": hit(baseline_rank, primary_budget) if baseline else None,
                    "rank_delta_vs_baseline": (
                        baseline_rank - rank
                        if isinstance(rank, int) and isinstance(baseline_rank, int)
                        else None
                    ),
                }
            )

        joined_count = sum(1 for rank in ranks if rank is not None)
        missing_recall_count = len(identities) - sum(1 for identity in identities if identity in recall)
        primary_hits = sum(1 for rank in ranks if hit(rank, primary_budget))
        clean = group_clean_enough(group, min_purity)
        budget_counts = {f"hit_at_{budget}": sum(1 for rank in ranks if hit(rank, budget)) for budget in budgets}
        baseline_primary_hits = None
        delta_primary_hits = None
        if baseline is not None:
            baseline_primary_hits = sum(1 for rank in baseline_ranks if hit(rank, primary_budget))
            delta_primary_hits = primary_hits - baseline_primary_hits

        attention: list[str] = []
        if "pending_review" in set(group.get("flags") or []):
            attention.append("guideline_pending_review")
        if not clean:
            attention.append("guideline_quality_attention")
        if clean and identities and primary_hits == 0:
            attention.append("embedding_or_candidate_recall_attention")
        if delta_primary_hits is not None and delta_primary_hits < 0:
            attention.append("recall_regression_attention")
        if delta_primary_hits is not None and delta_primary_hits > 0:
            attention.append("recall_gain_evidence")
        if missing_recall_count:
            attention.append("missing_recall_rows")

        group_diagnostics.append(
            {
                "guideline_id": guideline_id,
                "guideline_group_key": group.get("guideline_group_key"),
                "mechanism_id": group.get("mechanism_id"),
                "mechanism_name": group.get("mechanism_name"),
                "mechanism_family": group.get("mechanism_family"),
                "flags": group.get("flags") or [],
                "guideline_clean_enough": clean,
                "assigned_case_count": len(identities),
                "recall_joined_case_count": joined_count,
                "missing_recall_count": missing_recall_count,
                "primary_budget": primary_budget,
                "primary_hit_count": primary_hits,
                "primary_hit_rate": primary_hits / len(identities) if identities else None,
                "baseline_primary_hit_count": baseline_primary_hits,
                "delta_primary_hit_count": delta_primary_hits,
                "budget_hit_counts": budget_counts,
                "primary_hcvr_purity": group.get("primary_hcvr_purity"),
                "cwe_purity": group.get("cwe_purity"),
                "attention": attention,
                "example_misses": [
                    row["identity_key"]
                    for row in case_rows
                    if row["guideline_id"] == guideline_id and not row["hit_at_primary_budget"]
                ][:10],
            }
        )

    group_diagnostics.sort(
        key=lambda row: (
            "embedding_or_candidate_recall_attention" not in row["attention"],
            "recall_regression_attention" not in row["attention"],
            "guideline_quality_attention" not in row["attention"],
            -(row["assigned_case_count"] or 0),
            row["guideline_id"],
        )
    )
    case_rows.sort(key=lambda row: (row["guideline_id"], row["identity_key"]))

    attention_counts: dict[str, int] = defaultdict(int)
    for row in group_diagnostics:
        for item in row["attention"]:
            attention_counts[item] += 1
    summary = {
        "schema_version": "hcvr_guideline_recall_alignment.v1",
        "recall_label": recall_label,
        "baseline_label": baseline_label,
        "recall_case_count": len(recall_rows),
        "assigned_case_count": len(assigned_identities),
        "joined_recall_case_count": len(recall_joined_identities),
        "joined_baseline_case_count": len(baseline_joined_identities) if baseline is not None else None,
        "same_identity_baseline": same_identity_baseline,
        "group_count": len(group_diagnostics),
        "group_with_assignments_count": sum(1 for row in group_diagnostics if row["assigned_case_count"] > 0),
        "primary_budget": primary_budget,
        "budgets": budgets,
        "attention_counts": dict(sorted(attention_counts.items())),
        "interpretation": [
            "Guideline-group cleanliness and recall hit rates are separate evidence axes.",
            "A clean group with weak recall points to embedding, candidate slicing, or query wording mismatch.",
            "A dirty or pending group with weak recall should be fixed as guideline evidence before retraining.",
            "Baseline deltas are paper-facing only when same_identity_baseline is true.",
        ],
    }
    return summary, group_diagnostics, case_rows


def write_readme(path: Path, summary: dict[str, Any], group_rows: list[dict[str, Any]], recall_file: Path) -> None:
    lines = [
        "# Guideline Recall Alignment",
        "",
        "This report joins guideline-group diagnostics with recall ranks. It is for deciding whether a bad case is more likely a guideline-quality issue or an embedding/candidate-recall issue.",
        "",
        "It does not generate guidelines, change ranking, call an LLM, or add fallback rules.",
        "",
        "## Summary",
        "",
        f"- Recall table: `{recall_file}`",
        f"- Recall label: `{summary['recall_label']}`",
        f"- Baseline label: `{summary['baseline_label'] or 'none'}`",
        f"- Same identity baseline: {summary['same_identity_baseline']}",
        f"- Assigned cases: {summary['assigned_case_count']}",
        f"- Joined recall cases: {summary['joined_recall_case_count']} / {summary['recall_case_count']}",
        f"- Guideline groups: {summary['group_count']}",
        f"- Groups with assignments: {summary['group_with_assignments_count']}",
        f"- Primary budget: Top-{summary['primary_budget']}",
        f"- Attention counts: {summary['attention_counts']}",
        "",
        "## Highest Priority Groups",
        "",
        "| Guideline | Mechanism | Cases | Hit@Primary | Flags | Attention | Example Misses |",
        "| --- | --- | ---: | ---: | --- | --- | --- |",
    ]
    for row in group_rows[:25]:
        rate = row["primary_hit_rate"]
        hit_cell = "n/a" if rate is None else f"{row['primary_hit_count']}/{row['assigned_case_count']} ({rate:.2f})"
        lines.append(
            f"| `{row['guideline_id']}` | `{row.get('mechanism_id')}` | {row['assigned_case_count']} | "
            f"{hit_cell} | {','.join(row['flags'])} | {','.join(row['attention'])} | "
            f"{', '.join(row['example_misses'][:3])} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- If a guideline is clean enough but recall misses many assigned cases, inspect embedding behavior, candidate slicing, or query wording before changing the taxonomy.",
            "- If a guideline is mixed, pending, or lacks actionability fields, fix the guideline evidence and mechanism boundary before attributing failure to the embedding model.",
            "- If a baseline is provided and `same_identity_baseline` is false, treat deltas as debugging context only.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--group-report", type=Path, required=True)
    parser.add_argument("--case-assignments", type=Path, required=True)
    parser.add_argument("--recall-results", type=Path, required=True)
    parser.add_argument("--recall-label", default="recall")
    parser.add_argument("--baseline-results", type=Path)
    parser.add_argument("--baseline-label")
    parser.add_argument("--budgets", default=",".join(str(value) for value in DEFAULT_BUDGETS))
    parser.add_argument("--primary-budget", type=int, default=100)
    parser.add_argument("--min-clean-purity", type=float, default=0.67)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    budgets = parse_budgets(args.budgets)
    if args.primary_budget not in budgets:
        budgets = sorted({*budgets, args.primary_budget})
    summary, group_rows, case_rows = diagnose(
        group_rows=read_jsonl(args.group_report),
        assignments=load_assignments(args.case_assignments),
        recall_rows=read_jsonl(args.recall_results),
        recall_label=args.recall_label,
        baseline_rows=read_jsonl(args.baseline_results) if args.baseline_results else None,
        baseline_label=args.baseline_label,
        budgets=budgets,
        primary_budget=args.primary_budget,
        min_purity=args.min_clean_purity,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "group_recall_alignment.jsonl", group_rows)
    write_jsonl(args.output_dir / "case_recall_alignment.jsonl", case_rows)
    write_tsv(
        args.output_dir / "group_recall_alignment.tsv",
        group_rows,
        [
            "guideline_id",
            "mechanism_id",
            "assigned_case_count",
            "recall_joined_case_count",
            "primary_budget",
            "primary_hit_count",
            "primary_hit_rate",
            "baseline_primary_hit_count",
            "delta_primary_hit_count",
            "guideline_clean_enough",
            "flags",
            "attention",
            "example_misses",
        ],
    )
    write_readme(args.output_dir / "README.md", summary, group_rows, args.recall_results)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
