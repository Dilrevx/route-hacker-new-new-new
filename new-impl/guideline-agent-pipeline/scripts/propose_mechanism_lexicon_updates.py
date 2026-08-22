#!/usr/bin/env python3
"""Propose review-only mechanism lexicon updates from a revision backlog."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


STOP_WORDS = {
    "about",
    "after",
    "again",
    "against",
    "allow",
    "allows",
    "also",
    "and",
    "any",
    "are",
    "before",
    "being",
    "between",
    "both",
    "case",
    "cases",
    "code",
    "confirm",
    "controlled",
    "does",
    "each",
    "from",
    "guard",
    "into",
    "missing",
    "only",
    "path",
    "report",
    "safe",
    "should",
    "source",
    "sink",
    "that",
    "the",
    "their",
    "this",
    "through",
    "untrusted",
    "user",
    "values",
    "where",
    "with",
    "without",
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


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


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\t".join(fields) + "\n")
        for row in rows:
            handle.write("\t".join(format_tsv(row.get(field)) for field in fields) + "\n")


def slugify(text: str, *, prefix: str = "candidate_mech") -> str:
    value = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    value = re.sub(r"_+", "_", value)
    return f"{prefix}_{value[:72] or 'unknown'}"


def stable_id(*parts: str) -> str:
    digest = hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()[:12]
    return f"proposal_{digest}"


def token_terms(text: str, *, limit: int = 12) -> list[str]:
    tokens = [
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_.:-]*[a-z0-9]|[a-z0-9]", text.lower())
        if len(token) >= 3 and token not in STOP_WORDS
    ]
    return [token for token, _ in Counter(tokens).most_common(limit)]


def first_clause(text: str, *, limit: int = 120) -> str:
    cleaned = " ".join(text.split())
    if not cleaned:
        return ""
    head = re.split(r"(?<=[.;:])\s+", cleaned, maxsplit=1)[0]
    return head[:limit].rstrip(" ,.;:")


def load_existing_mechanisms(lexicon_path: Path | None) -> dict[str, dict[str, Any]]:
    if lexicon_path is None:
        return {}
    payload = read_json(lexicon_path)
    mechanisms = payload.get("mechanisms") if isinstance(payload, dict) else payload
    if not isinstance(mechanisms, list):
        return {}
    return {
        str(item.get("mechanism_id")): item
        for item in mechanisms
        if isinstance(item, dict) and item.get("mechanism_id")
    }


def proposal_priority(row: dict[str, Any]) -> tuple[int, float, int, str]:
    action_order = {
        "split_mechanism_boundary": 0,
        "revise_mechanism_text_from_evidence": 1,
        "collect_source_sink_guard_evidence": 2,
        "inspect_embedding_candidate_or_query_mismatch": 3,
        "inspect_same_identity_recall_regression": 4,
        "fix_recall_identity_join_or_run_coverage": 5,
    }
    min_score = row.get("min_score")
    score = float(min_score) if isinstance(min_score, (int, float)) else 1.0
    assigned = row.get("assigned_case_count")
    assigned_count = int(assigned) if isinstance(assigned, int) else 0
    return (action_order.get(row.get("recommended_action"), 9), score, -assigned_count, str(row.get("guideline_id") or ""))


def split_proposals(row: dict[str, Any]) -> list[dict[str, Any]]:
    suggestions = row.get("split_suggestions") if isinstance(row.get("split_suggestions"), list) else []
    proposals: list[dict[str, Any]] = []
    for index, suggestion in enumerate(suggestions, start=1):
        text = str(suggestion or "").strip()
        if not text:
            continue
        name = first_clause(text)
        proposals.append(
            {
                "proposal_id": stable_id(str(row.get("guideline_id") or ""), "split", str(index), text),
                "proposal_kind": "candidate_new_mechanism",
                "review_status": "needs_human_source_validation",
                "release_ready": False,
                "source_guideline_id": row.get("guideline_id"),
                "source_mechanism_id": row.get("mechanism_id"),
                "candidate_mechanism_id": slugify(name),
                "candidate_name": name,
                "candidate_guideline_text": str(row.get("candidate_guideline_text") or "").strip(),
                "candidate_keywords": token_terms(text + "\n" + str(row.get("candidate_guideline_text") or "")),
                "main_issue": row.get("main_issue"),
                "evidence_notes": row.get("evidence_notes") if isinstance(row.get("evidence_notes"), list) else [],
                "example_misses": row.get("example_misses") if isinstance(row.get("example_misses"), list) else [],
                "guardrails": [
                    "verify source/sink/guard evidence before adding to the lexicon",
                    "do not treat this proposal as a runtime matching rule",
                ],
            }
        )
    return proposals


def revise_proposal(row: dict[str, Any]) -> dict[str, Any] | None:
    text = str(row.get("candidate_guideline_text") or "").strip()
    if not text:
        return None
    return {
        "proposal_id": stable_id(str(row.get("guideline_id") or ""), "revise", text),
        "proposal_kind": "candidate_mechanism_revision",
        "review_status": "needs_human_source_validation",
        "release_ready": False,
        "source_guideline_id": row.get("guideline_id"),
        "target_mechanism_id": row.get("mechanism_id"),
        "target_mechanism_name": row.get("mechanism_name"),
        "candidate_guideline_text": text,
        "candidate_keywords": token_terms(text),
        "main_issue": row.get("main_issue"),
        "evidence_notes": row.get("evidence_notes") if isinstance(row.get("evidence_notes"), list) else [],
        "example_misses": row.get("example_misses") if isinstance(row.get("example_misses"), list) else [],
        "guardrails": [
            "treat this as a lexicon-review candidate, not a direct release edit",
            "confirm it generalizes beyond the motivating cases",
        ],
    }


def evidence_task(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "proposal_id": stable_id(str(row.get("guideline_id") or ""), "evidence", str(row.get("main_issue") or "")),
        "proposal_kind": "evidence_collection_task",
        "review_status": "needs_case_evidence",
        "release_ready": False,
        "source_guideline_id": row.get("guideline_id"),
        "target_mechanism_id": row.get("mechanism_id"),
        "target_mechanism_name": row.get("mechanism_name"),
        "main_issue": row.get("main_issue"),
        "evidence_notes": row.get("evidence_notes") if isinstance(row.get("evidence_notes"), list) else [],
        "example_misses": row.get("example_misses") if isinstance(row.get("example_misses"), list) else [],
        "guardrails": [
            "collect concrete source, sink, missing guard, and safe-fix evidence",
            "do not promote pending review groups into recall sidecars before evidence is checked",
        ],
    }


def recall_task(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "proposal_id": stable_id(str(row.get("guideline_id") or ""), "recall", ",".join(row.get("attention") or [])),
        "proposal_kind": "recall_investigation_task",
        "review_status": "needs_same_identity_recall_debug",
        "release_ready": False,
        "source_guideline_id": row.get("guideline_id"),
        "target_mechanism_id": row.get("mechanism_id"),
        "target_mechanism_name": row.get("mechanism_name"),
        "attention": row.get("attention") if isinstance(row.get("attention"), list) else [],
        "assigned_case_count": row.get("assigned_case_count"),
        "primary_hit_count": row.get("primary_hit_count"),
        "delta_primary_hit_count": row.get("delta_primary_hit_count"),
        "example_misses": row.get("example_misses") if isinstance(row.get("example_misses"), list) else [],
        "guardrails": [
            "inspect candidate slicing, query wording, embedding backend, and identity coverage separately",
            "do not change guideline taxonomy solely to improve a recall rank",
        ],
    }


def build_proposals(
    *,
    backlog_rows: list[dict[str, Any]],
    existing_mechanisms: dict[str, dict[str, Any]],
    max_items: int | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    proposals: list[dict[str, Any]] = []
    for row in sorted(backlog_rows, key=proposal_priority):
        action = row.get("recommended_action")
        if action == "split_mechanism_boundary":
            proposals.extend(split_proposals(row))
        elif action == "revise_mechanism_text_from_evidence":
            proposal = revise_proposal(row)
            if proposal:
                proposals.append(proposal)
        elif action == "collect_source_sink_guard_evidence":
            proposals.append(evidence_task(row))
        elif action in {
            "inspect_embedding_candidate_or_query_mismatch",
            "inspect_same_identity_recall_regression",
            "fix_recall_identity_join_or_run_coverage",
        }:
            proposals.append(recall_task(row))
    if max_items is not None:
        proposals = proposals[:max_items]

    kind_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    touched_existing = sorted(
        {
            str(row.get("target_mechanism_id") or row.get("source_mechanism_id") or "")
            for row in proposals
            if row.get("target_mechanism_id") or row.get("source_mechanism_id")
        }
        & set(existing_mechanisms)
    )
    for row in proposals:
        kind_counts[row["proposal_kind"]] = kind_counts.get(row["proposal_kind"], 0) + 1
        status_counts[row["review_status"]] = status_counts.get(row["review_status"], 0) + 1
    summary = {
        "schema_version": "hcvr_mechanism_lexicon_proposals.v1",
        "proposal_count": len(proposals),
        "proposal_kind_counts": dict(sorted(kind_counts.items())),
        "review_status_counts": dict(sorted(status_counts.items())),
        "existing_mechanism_count": len(existing_mechanisms),
        "touched_existing_mechanisms": touched_existing,
        "policy": [
            "This file is not a lexicon release and is not consumed by recall.",
            "Every candidate mechanism or revision requires source-evidence review before promotion.",
            "Recall investigation tasks must preserve same-identity evaluation boundaries.",
        ],
    }
    return summary, proposals


def write_readme(path: Path, summary: dict[str, Any], proposals: list[dict[str, Any]]) -> None:
    lines = [
        "# Mechanism Lexicon Proposal Backlog",
        "",
        "This artifact converts the r5 revision backlog into review-only lexicon proposals and recall investigation tasks.",
        "It is not a guideline release and is not consumed by online recall.",
        "",
        "## Summary",
        "",
        f"- Proposals: {summary['proposal_count']}",
        f"- Proposal kinds: {summary['proposal_kind_counts']}",
        f"- Review statuses: {summary['review_status_counts']}",
        f"- Existing mechanisms touched: {summary['touched_existing_mechanisms']}",
        "",
        "## First Items",
        "",
        "| Proposal | Kind | Source Guideline | Mechanism | Status | Name / Issue |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in proposals[:25]:
        name = row.get("candidate_name") or row.get("main_issue") or row.get("target_mechanism_name") or ""
        name = str(name).replace("|", "\\|")
        if len(name) > 160:
            name = name[:157] + "..."
        lines.append(
            f"| `{row['proposal_id']}` | `{row['proposal_kind']}` | `{row.get('source_guideline_id')}` | "
            f"`{row.get('target_mechanism_id') or row.get('source_mechanism_id')}` | "
            f"`{row.get('review_status')}` | {name} |"
        )
    lines.extend(
        [
            "",
            "## Promotion Rule",
            "",
            "A proposal can enter `mechanism_lexicon.seed.json` only after reviewer-confirmed source/sink/guard evidence and a fresh same-identity recall run for the resulting guideline sidecar.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision-backlog", type=Path, required=True)
    parser.add_argument("--lexicon", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-items", type=int)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    summary, proposals = build_proposals(
        backlog_rows=read_jsonl(args.revision_backlog),
        existing_mechanisms=load_existing_mechanisms(args.lexicon),
        max_items=args.max_items,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "lexicon_proposals.jsonl", proposals)
    write_tsv(
        args.output_dir / "lexicon_proposals.tsv",
        proposals,
        [
            "proposal_id",
            "proposal_kind",
            "review_status",
            "source_guideline_id",
            "target_mechanism_id",
            "source_mechanism_id",
            "candidate_mechanism_id",
            "candidate_name",
            "candidate_keywords",
            "example_misses",
            "main_issue",
        ],
    )
    write_readme(args.output_dir / "README.md", summary, proposals)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
