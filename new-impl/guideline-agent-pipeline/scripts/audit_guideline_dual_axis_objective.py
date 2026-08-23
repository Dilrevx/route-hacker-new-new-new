#!/usr/bin/env python3
"""Audit guideline generation against semantic-quality and recall-quality goals."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def status_for_semantic_quality(scorecard: dict[str, Any], worklist: dict[str, Any]) -> str:
    judge = scorecard.get("judge_evidence") if isinstance(scorecard.get("judge_evidence"), dict) else {}
    decision_counts = judge.get("decision_counts") if isinstance(judge.get("decision_counts"), dict) else {}
    accepted = int(decision_counts.get("accept") or 0)
    parsed = int(judge.get("parsed_count") or 0)
    worklist_count = int(worklist.get("worklist_count") or 0)
    if parsed and accepted == parsed and worklist_count == 0:
        return "satisfied"
    if parsed and accepted > 0:
        return "partially_satisfied_needs_evidence"
    return "not_satisfied_needs_semantic_evidence"


def status_for_recall(scorecard: dict[str, Any], desired_delta_rate: float) -> str:
    recall = scorecard.get("recall_evidence") if isinstance(scorecard.get("recall_evidence"), dict) else {}
    status = str(recall.get("status") or "")
    budgets = recall.get("budgets") if isinstance(recall.get("budgets"), list) else []
    max_delta = max((float(row.get("delta_rate") or 0.0) for row in budgets), default=0.0)
    if status in {"valid_same_identity", "inherited_same_identity_by_sidecar_equivalence"}:
        if max_delta >= desired_delta_rate:
            return "satisfied_for_reported_same_identity_budget"
        return "compatible_but_improvement_below_target"
    if status:
        return f"not_satisfied_{status}"
    return "not_satisfied_missing_recall_evidence"


def source_reviewed_boundary_evidence(
    ledger_validation: dict[str, Any] | None,
    ledger_judge: dict[str, Any] | None,
) -> dict[str, Any]:
    if not ledger_validation and not ledger_judge:
        return {
            "status": "not_provided",
            "message": "No source-reviewed boundary ledger evidence was provided.",
        }

    valid_count = int((ledger_validation or {}).get("valid_count") or 0)
    invalid_count = int((ledger_validation or {}).get("invalid_count") or 0)
    promotable_count = int((ledger_validation or {}).get("promotable_count") or 0)
    parsed = int((ledger_judge or {}).get("parsed_count") or 0)
    accepted = int((ledger_judge or {}).get("accepted_count") or 0)
    low_score_count = int((ledger_judge or {}).get("low_score_count") or 0)
    if invalid_count:
        status = "not_satisfied_invalid_source_reviewed_ledger"
    elif valid_count and parsed and accepted == parsed:
        status = "satisfied_for_source_reviewed_boundaries"
    elif valid_count:
        status = "partially_satisfied_source_reviewed_boundaries_need_judge_or_revision"
    else:
        status = "not_satisfied_missing_source_reviewed_boundaries"
    return {
        "status": status,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "promotable_count": promotable_count,
        "validation_decision_counts": (ledger_validation or {}).get("decision_counts") or {},
        "judge_parsed_count": parsed,
        "judge_accepted_count": accepted,
        "judge_low_score_count": low_score_count,
        "judge_decision_counts": (ledger_judge or {}).get("decision_counts") or {},
        "judge_average_scores": (ledger_judge or {}).get("average_scores") or {},
        "message": (
            "Source-reviewed boundary evidence is semantic QA only. It can justify a boundary as review-ready, "
            "but it does not prove embedding recall."
        ),
    }


def build_audit(
    *,
    scorecard: dict[str, Any],
    worklist: dict[str, Any],
    desired_delta_rate: float,
    boundary_recall_triage: dict[str, Any] | None = None,
    ledger_validation: dict[str, Any] | None = None,
    ledger_judge: dict[str, Any] | None = None,
) -> dict[str, Any]:
    recall = scorecard.get("recall_evidence") if isinstance(scorecard.get("recall_evidence"), dict) else {}
    judge = scorecard.get("judge_evidence") if isinstance(scorecard.get("judge_evidence"), dict) else {}
    structural = scorecard.get("structural_evidence") if isinstance(scorecard.get("structural_evidence"), dict) else {}
    recall_equivalence = (
        scorecard.get("recall_equivalence_evidence")
        if isinstance(scorecard.get("recall_equivalence_evidence"), dict)
        else {}
    )
    semantic_status = status_for_semantic_quality(scorecard, worklist)
    recall_status = status_for_recall(scorecard, desired_delta_rate)
    reviewed_boundary = source_reviewed_boundary_evidence(ledger_validation, ledger_judge)
    boundary_recall_triage = boundary_recall_triage or {}
    boundary_next_actions = (
        boundary_recall_triage.get("next_action_counts")
        if isinstance(boundary_recall_triage.get("next_action_counts"), dict)
        else {}
    )
    aligned_boundary_count = int(
        boundary_next_actions.get("semantic_boundary_and_recall_examples_are_aligned_for_next_ablation")
        or 0
    )
    requirements = [
        {
            "requirement": "Design reusable guideline classification that generalizes across CVEs but remains audit-specific.",
            "evidence": [
                "mechanism guideline generator uses offline mechanism attribution, member evidence support, release-ready gating, and review queue quarantine",
                f"weighted_primary_hcvr_purity={structural.get('weighted_primary_hcvr_purity')}",
                f"weighted_cwe_purity={structural.get('weighted_cwe_purity')}",
                f"judge_decision_counts={judge.get('decision_counts')}",
                f"evidence_worklist_actions={worklist.get('action_counts')}",
                f"source_reviewed_boundary_status={reviewed_boundary.get('status')}",
                f"source_reviewed_boundary_validation_decisions={reviewed_boundary.get('validation_decision_counts')}",
                f"source_reviewed_boundary_judge_decisions={reviewed_boundary.get('judge_decision_counts')}",
            ],
            "status": semantic_status,
            "gap": "TraeX judge still finds many groups needing source/sink/guard evidence or split/revision work.",
        },
        {
            "requirement": "Keep guidelines compatible with the tuned embedding recall path.",
            "evidence": [
                f"recall_status={recall.get('status')}",
                f"same_identity_set={recall.get('same_identity_set')}",
                f"same_identity_order={recall.get('same_identity_order')}",
                f"recall_equivalence_status={recall_equivalence.get('status')}",
                f"primary_budget={recall.get('primary_budget')}",
                f"boundary_recall_triage_aligned_boundaries={aligned_boundary_count}",
                f"boundary_recall_triage_rank_tables={boundary_recall_triage.get('rank_table_labels')}",
            ],
            "status": recall_status,
            "gap": "The current r8 recall evidence is inherited by unchanged sidecar text; a fresh run is required after any consumed guideline text changes.",
        },
        {
            "requirement": "Use recall bad cases as motivation without turning them into answer keys.",
            "evidence": [
                "known anchors are used after ranking for metrics, not for query construction",
                "evidence worklist marks judge/bad-case material as review_only_not_release_not_recall_input",
                "README forbids runtime regex fallback, hidden label routing, and per-case fixes",
            ],
            "status": "satisfied_by_current_policy",
            "gap": "Must be rechecked whenever generator or recall query construction changes.",
        },
        {
            "requirement": "If semantic guideline quality is strong but recall remains weak, inspect recall method before weakening taxonomy.",
            "evidence": [
                "README separates semantic guideline quality from embedding recall compatibility",
                "revision backlog has actions for embedding/candidate/query mismatch",
                "scorecard separates structural, judge, recall, and sidecar-equivalence evidence",
                "source-reviewed boundaries can be marked semantically ready without being counted as recall-proven",
            ],
            "status": "satisfied_as_evaluation_policy",
            "gap": "Need per-group semantic-vs-recall triage after the next changed-sidecar recall run.",
        },
        {
            "requirement": "Avoid hardcoding and be cautious with paper-facing engineering combinations.",
            "evidence": [
                "scorecard marks recall improvement claim as not_supported_at_desired_delta",
                "RRF/fusion is documented as a recall-compatible engineering path, not a guideline-quality claim",
                "TraeX judge output feeds backlog/worklist rather than released guidelines or ranking",
                "new embedders, fusion, or rerankers are allowed only as explicit same-identity A/B configurations",
            ],
            "status": "satisfied_by_current_policy",
            "gap": "Any future fusion or model substitution needs same-identity A/B and a separate claim boundary.",
        },
    ]
    missing = [
        row
        for row in requirements
        if not str(row["status"]).startswith("satisfied")
        and str(row["status"]) not in {"satisfied_as_evaluation_policy", "satisfied_by_current_policy"}
    ]
    next_gates = [
        {
            "gate": "semantic_evidence_gate",
            "run_when": "before changing released guideline text or lexicon entries",
            "pass_condition": "each promoted group has checked source, sink, missing guard, exploit precondition, and fix semantics for representative member cases",
            "current_state": "not passed; evidence worklist has outstanding rows",
        },
        {
            "gate": "same_identity_recall_gate",
            "run_when": "after recall-consumed guideline sidecar text changes",
            "pass_condition": "same_identity_set=true and same_identity_order=true against the frozen comparison baseline",
            "current_state": "not required for r8 equivalence; required for any next changed sidecar",
        },
        {
            "gate": "taxonomy_vs_embed_triage_gate",
            "run_when": "when a semantically clean group misses Top-K",
            "pass_condition": "record whether the miss is caused by guideline wording, candidate slicing, embedding backend, adapter weights, rank fusion, or audit budget",
            "current_state": (
                f"policy exists; {aligned_boundary_count} source-reviewed boundary/boundaries currently have "
                "same-identity recall examples aligned"
                if aligned_boundary_count
                else "policy exists; needs per-group run after next recall table"
            ),
        },
        {
            "gate": "recall_method_substitution_gate",
            "run_when": "when a source-reviewed guideline is coherent but the current embedding recall misses representative cases",
            "pass_condition": "compare any replacement embedder, reranker, or fusion method on the same identities, snapshots, candidates, and budgets without regex fallback or label routing",
            "current_state": "allowed by policy; no paper-facing method substitution claim until same-identity evidence exists",
        },
        {
            "gate": "paper_claim_boundary_gate",
            "run_when": "before writing results into the paper",
            "pass_condition": "semantic judge evidence, source-reviewed boundary evidence, structural diagnostics, sidecar equivalence, recall A/B deltas, and engineering fusion are reported as separate claims",
            "current_state": "satisfied by current scorecard format, but final paper table still needs fresh numbers if guideline text changes",
        },
    ]
    overall_status = "not_complete" if missing else "complete"
    return {
        "schema_version": "hcvr_guideline_dual_axis_objective_audit.v1",
        "desired_delta_rate": desired_delta_rate,
        "overall_status": overall_status,
        "requirements": requirements,
        "source_reviewed_boundary_evidence": reviewed_boundary,
        "missing_or_incomplete_requirements": missing,
        "next_gates": next_gates,
        "decision": (
            "Continue guideline-v2 work through evidence collection before rewriting released guidelines. "
            "Do not mark the objective complete until semantic evidence improves and any changed sidecar has a fresh same-identity recall evaluation."
        )
        if missing
        else "Objective is covered by current artifacts.",
    }


def write_readme(path: Path, audit: dict[str, Any]) -> None:
    lines = [
        "# Guideline Dual-Axis Objective Audit",
        "",
        "This audit checks the current guideline-v2 state against two coupled goals:",
        "",
        "1. produce reusable, semantically accurate CVE-mechanism guidelines for audit;",
        "2. keep those guidelines compatible with the tuned embedding recall path.",
        "",
        "It is a completion audit, not a release file and not a recall input.",
        "",
        "## Overall Status",
        "",
        f"- Status: `{audit['overall_status']}`",
        f"- Desired recall delta rate: {audit['desired_delta_rate']:.4f}",
        f"- Decision: {audit['decision']}",
        "",
        "## Prompt-To-Artifact Checklist",
        "",
        "| Requirement | Status | Evidence | Gap |",
        "| --- | --- | --- | --- |",
    ]
    for row in audit["requirements"]:
        evidence = "<br>".join(str(item).replace("|", "\\|") for item in row["evidence"])
        gap = str(row.get("gap") or "").replace("|", "\\|")
        lines.append(f"| {row['requirement']} | `{row['status']}` | {evidence} | {gap} |")
    reviewed = audit.get("source_reviewed_boundary_evidence") or {}
    lines.extend(
        [
            "",
            "## Source-Reviewed Boundary Evidence",
            "",
            f"- Status: `{reviewed.get('status')}`",
            f"- Ledger valid/invalid: {reviewed.get('valid_count')} / {reviewed.get('invalid_count')}",
            f"- Promotable boundaries: {reviewed.get('promotable_count')}",
            f"- Ledger decisions: {reviewed.get('validation_decision_counts')}",
            f"- Judge decisions: {reviewed.get('judge_decision_counts')}",
            f"- Judge average scores: {reviewed.get('judge_average_scores')}",
            "",
            "This section records source-reviewed guideline-boundary evidence. It can support a semantic boundary decision, but it does not prove recall. If one of these boundaries misses Top-K, the next action is recall-side diagnosis or a same-identity model/ranking A/B, not automatic taxonomy degradation.",
        ]
    )
    lines.extend(
        [
            "",
            "## Required Gates For The Next Round",
            "",
            "| Gate | Run When | Pass Condition | Current State |",
            "| --- | --- | --- | --- |",
        ]
    )
    for row in audit["next_gates"]:
        lines.append(
            f"| `{row['gate']}` | {row['run_when']} | {row['pass_condition']} | {row['current_state']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "The current r8 line is methodologically cleaner than earlier iterations: unresolved groups are quarantined, "
            "TraeX judge output is advisory, and recall evidence is separated from semantic quality. The objective is "
            "still not complete because many reviewed groups need source/sink/guard evidence and the r8 recall evidence "
            "is inherited through sidecar equivalence rather than a fresh run after changed guideline text.",
            "",
            "The next concrete work is therefore evidence collection and mechanism-boundary repair, followed by a fresh "
            "same-identity P3C64 recall run only after the recall-consumed sidecar text changes.",
            "",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scorecard", type=Path, required=True)
    parser.add_argument("--evidence-worklist-summary", type=Path, required=True)
    parser.add_argument("--boundary-recall-triage-summary", type=Path)
    parser.add_argument("--ledger-validation-summary", type=Path)
    parser.add_argument("--ledger-judge-summary", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--desired-delta-rate", type=float, default=0.10)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    audit = build_audit(
        scorecard=read_json(args.scorecard),
        worklist=read_json(args.evidence_worklist_summary),
        desired_delta_rate=args.desired_delta_rate,
        boundary_recall_triage=(
            read_json(args.boundary_recall_triage_summary)
            if args.boundary_recall_triage_summary
            else None
        ),
        ledger_validation=read_json(args.ledger_validation_summary) if args.ledger_validation_summary else None,
        ledger_judge=read_json(args.ledger_judge_summary) if args.ledger_judge_summary else None,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", audit)
    write_readme(args.output_dir / "README.md", audit)
    print(json.dumps({"overall_status": audit["overall_status"], "missing_count": len(audit["missing_or_incomplete_requirements"])}, sort_keys=True))


if __name__ == "__main__":
    main()
