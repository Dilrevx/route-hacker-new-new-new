# HCVR Guideline Experiment Scorecard

- Release: `guideline-v2-r8-source-reviewed-release-candidate`
- Guidelines: 33
- Work items: n/a
- Active attributions: n/a
- Pending review: n/a
- Release-ready guidelines: 12
- Review-only guidelines: 21
- Case assignments: 48
- Input boundaries: 33
- Unresolved representatives: 5
- Include singleton overrides: False
- Recall sidecar rows: 32
- Pending overrides included: n/a

## Evidence Axes

| Axis | Status | Main Evidence | Boundary |
| --- | --- | --- | --- |
| Guideline grouping | advisory_structural_diagnostic | 28 evaluated groups, weighted HCVR purity 0.9375, weighted CWE purity 0.9375 | Structural labels are triage signals for guideline grouping, not hard pass/fail gates. |
| LLM semantic judge | missing | parsed 0/0, accepted 0, low-score 0 | No LLM judge summary was provided; semantic review evidence is missing. |
| Embedding recall | invalid_sidecar_equivalence | common identities 143 | A recall comparison was provided, but the requested release sidecar changes recall-consumed identity keys or guideline text. Rerun recall for this release before making retrieval claims. |
| Recall sidecar equivalence | invalid_consumed_text_difference | changed consumed texts 28 | The released sidecar changes recall-consumed identity keys or guideline text; rerun recall before inheriting metrics. |

## Sidecar Equivalence

- Compared sidecars: `guideline-v2-r8-release-ready-sidecar` vs `source-reviewed-release-candidate-sidecar`
- Same key set: False
- Changed consumed guideline texts: 28
- Recall-consumed text equivalent: False

This evidence only covers the guideline text passed into retrieval. It does not cover changes to identities, source snapshots, slicing, embedding service, adapter weights, or ranking parameters.

## Claim Boundaries

- `guideline_classification_quality`: supported_as_advisory_diagnostic. Evidence: group structural summary; source-only and pending-review accounting. Caveat: Purity and flags are weak diagnostics; mechanism quality still needs semantic review.
- `semantic_guideline_quality`: missing_evidence. Evidence: none. Caveat: Judge outputs rank review priority and cannot be converted into hardcoded routing.
- `embedding_recall_improvement`: missing_or_invalid_evidence. Evidence: none. Caveat: A recall comparison was provided, but the requested release sidecar changes recall-consumed identity keys or guideline text. Rerun recall for this release before making retrieval claims.

## Policy

- Optimize guideline wording and grouping from source/sink/guard evidence, not from keyword checks.
- Use bad recall cases as regression and motivation data, not as per-case hardcoded fixes.
- Treat recall numbers as evidence for a specific embedding plus guideline/query configuration.
- Require same identity sets for paper-facing recall deltas.

## Interpretation

A recall-improvement claim needs same-identity A/B evidence and should only name budgets whose delta is at least 10.0% when using a percentage-point threshold.
A guideline-classification claim can cite structural and LLM-judge diagnostics, but those diagnostics remain advisory and should drive source-evidence review rather than hardcoded keyword rules.
