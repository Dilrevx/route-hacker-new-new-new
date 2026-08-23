#!/usr/bin/env python3
"""Triage source-reviewed guideline boundaries against recall evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_BUDGETS = (30, 50, 100, 150, 200)
REQUIRED_PROMOTION_FIELDS = [
    "source_shape",
    "sink_or_sensitive_effect",
    "missing_guard",
    "exploit_precondition",
    "safe_fix_semantics",
    "boundary_decision",
]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            row = json.loads(line)
            row["_line_no"] = line_no
            rows.append(row)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def parse_budgets(text: str) -> list[int]:
    budgets: list[int] = []
    for item in text.split(","):
        value = item.strip()
        if not value:
            continue
        budget = int(value)
        if budget < 1:
            raise ValueError("budgets must be positive")
        budgets.append(budget)
    if not budgets:
        raise ValueError("at least one budget is required")
    return sorted(set(budgets))


def parse_rank_table_arg(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError("--rank-table must use LABEL=PATH")
    label, path = value.split("=", 1)
    label = label.strip()
    if not label:
        raise ValueError("--rank-table label cannot be empty")
    return label, Path(path)


def is_filled(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip()) and value.strip().lower() not in {"n/a", "todo", "tbd"}
    if isinstance(value, list):
        return bool(value)
    return True


def semantic_status(row: dict[str, Any]) -> tuple[str, list[str]]:
    decision = str(row.get("boundary_decision") or "").strip()
    missing: list[str] = []
    if decision != "promote_boundary":
        return "not_promoted", ["boundary_decision"]
    for field in REQUIRED_PROMOTION_FIELDS:
        if not is_filled(row.get(field)):
            missing.append(field)
    if not is_filled(row.get("representative_cases")):
        missing.append("representative_cases")
    if missing:
        return "promotion_incomplete", missing
    return "source_reviewed_promotable", []


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


def index_rank_table(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        identity = row.get("identity_key")
        if isinstance(identity, str) and identity and identity not in indexed:
            indexed[identity] = row
    return indexed


def case_recall(identity: str, rank_tables: dict[str, dict[str, dict[str, Any]]], budgets: list[int]) -> dict[str, Any]:
    per_table: dict[str, Any] = {}
    present_any = False
    for label, table in rank_tables.items():
        row = table.get(identity)
        if not row:
            per_table[label] = {"present": False, "rank": None, "hits": {}}
            continue
        present_any = True
        rank = best_rank(row)
        per_table[label] = {
            "present": True,
            "rank": rank,
            "candidate_count": row.get("candidate_count"),
            "state": row.get("state"),
            "hits": {f"hit_at_{budget}": rank is not None and rank <= budget for budget in budgets},
        }
    return {"identity_key": identity, "present_in_any_rank_table": present_any, "rank_tables": per_table}


def aggregate_recall(case_rows: list[dict[str, Any]], labels: list[str], budgets: list[int], primary_budget: int) -> dict[str, Any]:
    aggregate: dict[str, Any] = {}
    for label in labels:
        present = [case for case in case_rows if case["rank_tables"][label]["present"]]
        missing = [case for case in case_rows if not case["rank_tables"][label]["present"]]
        budget_hits: dict[str, Any] = {}
        for budget in budgets:
            hit_count = sum(1 for case in present if case["rank_tables"][label]["hits"][f"hit_at_{budget}"])
            budget_hits[f"hit_at_{budget}"] = {
                "hit_count": hit_count,
                "present_count": len(present),
                "representative_count": len(case_rows),
                "hit_rate_on_present": hit_count / len(present) if present else None,
                "hit_rate_on_representatives": hit_count / len(case_rows) if case_rows else None,
            }
        primary = budget_hits[f"hit_at_{primary_budget}"]
        if missing:
            status = "recall_coverage_gap"
            next_action = "run_same_identity_recall_for_representative_cases_or_use_a_matching_rank_table"
        elif not present:
            status = "recall_not_evaluated"
            next_action = "provide_same_identity_rank_table_before_making_recall_claim"
        elif primary["hit_count"] == len(present):
            status = "recall_supported_for_boundary_examples"
            next_action = "candidate_for_sidecar_ablation_after_release_text_changes"
        elif primary["hit_count"] == 0:
            status = "recall_miss_for_boundary_examples"
            next_action = "inspect_query_wording_candidate_slicing_embedding_backend_or_ranking"
        else:
            status = "recall_partial_for_boundary_examples"
            next_action = "compare_hit_and_miss_cases_before_changing_guideline_boundary"
        aggregate[label] = {
            "status": status,
            "next_action": next_action,
            "present_count": len(present),
            "missing_count": len(missing),
            "representative_count": len(case_rows),
            "budget_hits": budget_hits,
            "missing_identities": [case["identity_key"] for case in missing],
        }
    return aggregate


def boundary_next_action(semantic: str, recall: dict[str, Any]) -> str:
    if semantic != "source_reviewed_promotable":
        return "collect_source_sink_guard_fix_evidence_before_recall_interpretation"
    statuses = {value["status"] for value in recall.values()}
    if not recall:
        return "attach_same_identity_recall_evidence"
    if "recall_coverage_gap" in statuses or "recall_not_evaluated" in statuses:
        return "run_same_identity_recall_for_this_boundary_before_claiming_embedding_effect"
    if "recall_miss_for_boundary_examples" in statuses or "recall_partial_for_boundary_examples" in statuses:
        return "preserve_semantic_boundary_and_debug_recall_side"
    return "semantic_boundary_and_recall_examples_are_aligned_for_next_ablation"


def build_triage(
    *,
    ledger_rows: list[dict[str, Any]],
    rank_tables: dict[str, list[dict[str, Any]]],
    budgets: list[int],
    primary_budget: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    indexed_tables = {label: index_rank_table(rows) for label, rows in rank_tables.items()}
    labels = list(indexed_tables)
    triage_rows: list[dict[str, Any]] = []
    for row in ledger_rows:
        representative_cases = row.get("representative_cases") if isinstance(row.get("representative_cases"), list) else []
        case_rows = [case_recall(str(identity), indexed_tables, budgets) for identity in representative_cases]
        sem_status, missing_fields = semantic_status(row)
        recall_summary = aggregate_recall(case_rows, labels, budgets, primary_budget) if labels else {}
        triage_rows.append(
            {
                "guideline_id": row.get("guideline_id"),
                "mechanism_id": row.get("mechanism_id"),
                "boundary_label": row.get("boundary_label"),
                "boundary_decision": row.get("boundary_decision"),
                "semantic_status": sem_status,
                "semantic_missing_fields": missing_fields,
                "representative_case_count": len(representative_cases),
                "representative_cases": representative_cases,
                "recall": recall_summary,
                "case_recall": case_rows,
                "next_action": boundary_next_action(sem_status, recall_summary),
                "policy": "review_only_does_not_change_guidelines_or_ranking",
            }
        )
    summary = {
        "schema_version": "hcvr_guideline_boundary_recall_triage.v1",
        "boundary_count": len(triage_rows),
        "rank_table_labels": labels,
        "budgets": budgets,
        "primary_budget": primary_budget,
        "semantic_status_counts": count_by(triage_rows, "semantic_status"),
        "next_action_counts": count_by(triage_rows, "next_action"),
        "policy": [
            "Source-reviewed guideline boundaries and embedding recall evidence are separate axes.",
            "Bad recall cases can motivate query, slicing, embedding, or ranking investigation, but they are not per-case guideline fixes.",
            "A promotable boundary is semantically ready only; it becomes recall-proven only after same-identity rank evidence covers its representative cases.",
            "This report does not update released guidelines, sidecars, rank tables, or audit prompts.",
        ],
    }
    return summary, triage_rows


def count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "missing")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def fmt_cell(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) or "n/a"
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).replace("\n", " ").replace("|", "\\|") or "n/a"


def write_readme(path: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Guideline Boundary Recall Triage",
        "",
        "This report joins source-reviewed guideline boundary ledger rows with optional recall rank tables.",
        "It separates semantic boundary quality from retrieval performance so bad cases can drive investigation without becoming hardcoded routing.",
        "",
        "## Summary",
        "",
        f"- Boundaries: {summary['boundary_count']}",
        f"- Rank tables: {fmt_cell(summary['rank_table_labels'])}",
        f"- Primary budget: Top-{summary['primary_budget']}",
        f"- Semantic statuses: {summary['semantic_status_counts']}",
        f"- Next actions: {summary['next_action_counts']}",
        "",
        "## Boundary Rows",
        "",
        "| Guideline | Boundary | Semantic Status | Representatives | Recall Status | Next Action |",
        "| --- | --- | --- | ---: | --- | --- |",
    ]
    for row in rows:
        recall_status = {
            label: value["status"]
            for label, value in (row.get("recall") or {}).items()
        }
        lines.append(
            f"| `{fmt_cell(row.get('guideline_id'))}` | `{fmt_cell(row.get('boundary_label'))}` | "
            f"`{fmt_cell(row.get('semantic_status'))}` | {row.get('representative_case_count')} | "
            f"{fmt_cell(recall_status)} | `{fmt_cell(row.get('next_action'))}` |"
        )
    lines.extend(["", "## Case Recall Details", ""])
    for row in rows:
        lines.append(f"### {row.get('guideline_id')} / {row.get('boundary_label')}")
        lines.append("")
        lines.append("| Identity | Rank Table | Present | Rank | Primary Hit |")
        lines.append("| --- | --- | --- | ---: | --- |")
        for case in row.get("case_recall") or []:
            for label, recall in (case.get("rank_tables") or {}).items():
                hits = recall.get("hits") or {}
                primary_hit_key = f"hit_at_{summary['primary_budget']}"
                lines.append(
                    f"| `{fmt_cell(case.get('identity_key'))}` | `{fmt_cell(label)}` | "
                    f"{recall.get('present')} | {fmt_cell(recall.get('rank'))} | "
                    f"{hits.get(primary_hit_key, False)} |"
                )
        lines.append("")
    lines.extend(["## Policy", ""])
    for item in summary["policy"]:
        lines.append(f"- {item}")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--rank-table", action="append", default=[], help="LABEL=PATH; may be repeated")
    parser.add_argument("--budgets", default=",".join(str(item) for item in DEFAULT_BUDGETS))
    parser.add_argument("--primary-budget", type=int, default=100)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    budgets = parse_budgets(args.budgets)
    if args.primary_budget not in budgets:
        budgets = sorted(set(budgets + [args.primary_budget]))
    rank_tables: dict[str, list[dict[str, Any]]] = {}
    for item in args.rank_table:
        label, path = parse_rank_table_arg(item)
        rank_tables[label] = read_jsonl(path)
    summary, rows = build_triage(
        ledger_rows=read_jsonl(args.ledger),
        rank_tables=rank_tables,
        budgets=budgets,
        primary_budget=args.primary_budget,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "boundary_recall_triage.jsonl", rows)
    write_readme(args.output_dir / "README.md", summary, rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
