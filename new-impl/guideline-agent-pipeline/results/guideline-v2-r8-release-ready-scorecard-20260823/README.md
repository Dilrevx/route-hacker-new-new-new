# HCVR Guideline Experiment Scorecard

- Release: `guideline-v2-r8-release-ready`
- Guidelines: 177
- Work items: 746
- Active attributions: 360
- Pending review: 386
- Recall sidecar rows: 189
- Pending overrides included: False

## Evidence Axes

| Axis | Status | Main Evidence | Boundary |
| --- | --- | --- | --- |
| Guideline grouping | advisory_structural_diagnostic | 119 evaluated groups, weighted HCVR purity 0.8659, weighted CWE purity 0.9245 | Structural labels are triage signals for guideline grouping, not hard pass/fail gates. |
| LLM semantic judge | advisory_semantic_diagnostic | parsed 20/20, accepted 2, low-score 14 | LLM-as-judge output is semantic review evidence; it must not become keyword routing or a hidden optimization target. |
| Embedding recall | missing | common identities 0 | No recall A/B summary was provided; do not make embedding recall claims. |

## Claim Boundaries

- `guideline_classification_quality`: supported_as_advisory_diagnostic. Evidence: group structural summary; source-only and pending-review accounting. Caveat: Purity and flags are weak diagnostics; mechanism quality still needs semantic review.
- `semantic_guideline_quality`: supported_as_advisory_diagnostic. Evidence: LLM-as-judge summary. Caveat: Judge outputs rank review priority and cannot be converted into hardcoded routing.
- `embedding_recall_improvement`: missing_or_invalid_evidence. Evidence: none. Caveat: No recall A/B summary was provided; do not make embedding recall claims.

## Policy

- Optimize guideline wording and grouping from source/sink/guard evidence, not from keyword checks.
- Use bad recall cases as regression and motivation data, not as per-case hardcoded fixes.
- Treat recall numbers as evidence for a specific embedding plus guideline/query configuration.
- Require same identity sets for paper-facing recall deltas.

## Interpretation

A recall-improvement claim needs same-identity A/B evidence and should only name budgets whose delta is at least 10.0% when using a percentage-point threshold.
A guideline-classification claim can cite structural and LLM-judge diagnostics, but those diagnostics remain advisory and should drive source-evidence review rather than hardcoded keyword rules.
