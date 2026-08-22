# HCVR Guideline Experiment Scorecard

- Release: `guideline-v2-r6-candidate`
- Guidelines: 433
- Work items: 760
- Active attributions: 612
- Pending review: 148
- Recall sidecar rows: 252
- Pending overrides included: False

## Evidence Axes

| Axis | Status | Main Evidence | Boundary |
| --- | --- | --- | --- |
| Guideline grouping | advisory_structural_diagnostic | 103 evaluated groups, weighted HCVR purity 0.8297, weighted CWE purity 0.9142 | Structural labels are triage signals for guideline grouping, not hard pass/fail gates. |
| LLM semantic judge | missing | parsed 0/0, accepted 0, low-score 0 | No LLM judge summary was provided; semantic review evidence is missing. |
| Embedding recall | missing | common identities 0 | No recall A/B summary was provided; do not make embedding recall claims. |

## Claim Boundaries

- `guideline_classification_quality`: supported_as_advisory_diagnostic. Evidence: group structural summary; source-only and pending-review accounting. Caveat: Purity and flags are weak diagnostics; mechanism quality still needs semantic review.
- `semantic_guideline_quality`: missing_evidence. Evidence: none. Caveat: Judge outputs rank review priority and cannot be converted into hardcoded routing.
- `embedding_recall_improvement`: missing_or_invalid_evidence. Evidence: none. Caveat: No recall A/B summary was provided; do not make embedding recall claims.

## Policy

- Optimize guideline wording and grouping from source/sink/guard evidence, not from keyword checks.
- Use bad recall cases as regression and motivation data, not as per-case hardcoded fixes.
- Treat recall numbers as evidence for a specific embedding plus guideline/query configuration.
- Require same identity sets for paper-facing recall deltas.

## Interpretation

A recall-improvement claim needs same-identity A/B evidence and should only name budgets whose delta is at least 10.0% when using a percentage-point threshold.
A guideline-classification claim can cite structural and LLM-judge diagnostics, but those diagnostics remain advisory and should drive source-evidence review rather than hardcoded keyword rules.
