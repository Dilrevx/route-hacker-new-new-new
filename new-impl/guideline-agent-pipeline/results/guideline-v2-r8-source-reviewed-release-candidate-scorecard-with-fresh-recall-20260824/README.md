# HCVR Guideline Experiment Scorecard

- Release: `guideline-v2-r8-source-reviewed-release-candidate-fresh-qwen06b-top200-32`
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
| Embedding recall | valid_same_identity | common identities 32 | Recall A/B evidence is valid for retrieval claims because both sides use the same identity set. |
| Recall sidecar equivalence | missing | changed consumed texts n/a | No guideline sidecar equivalence report was provided. |

## Recall Budget Deltas

Left: `source-reviewed-release-candidate`
Right: `r8-release-ready-sidecar`

| Budget | Left | Right | Delta Cases | Delta Rate |
| ---: | ---: | ---: | ---: | ---: |
| Top-30 | 23 | 16 | 7 | 21.9% |
| Top-50 | 24 | 17 | 7 | 21.9% |
| Top-100 | 28 | 21 | 7 | 21.9% |
| Top-150 | 28 | 23 | 5 | 15.6% |
| Top-200 | 29 | 23 | 6 | 18.8% |
| MRR | 0.262389 | 0.210817 | 0.051571 | n/a |

## Claim Boundaries

- `guideline_classification_quality`: supported_as_advisory_diagnostic. Evidence: group structural summary; source-only and pending-review accounting. Caveat: Purity and flags are weak diagnostics; mechanism quality still needs semantic review.
- `semantic_guideline_quality`: missing_evidence. Evidence: none. Caveat: Judge outputs rank review priority and cannot be converted into hardcoded routing.
- `embedding_recall_improvement`: supported_for_reported_budgets. Evidence: Hit@30 delta 7 cases / 21.9%; Hit@50 delta 7 cases / 21.9%; Hit@100 delta 7 cases / 21.9%; Hit@150 delta 5 cases / 15.6%; Hit@200 delta 6 cases / 18.8%. Caveat: This claim is about the evaluated embedding plus guideline/query configuration, not guideline taxonomy quality alone.

## Policy

- Optimize guideline wording and grouping from source/sink/guard evidence, not from keyword checks.
- Use bad recall cases as regression and motivation data, not as per-case hardcoded fixes.
- Treat recall numbers as evidence for a specific embedding plus guideline/query configuration.
- Require same identity sets for paper-facing recall deltas.

## Interpretation

A recall-improvement claim needs same-identity A/B evidence and should only name budgets whose delta is at least 10.0% when using a percentage-point threshold.
A guideline-classification claim can cite structural and LLM-judge diagnostics, but those diagnostics remain advisory and should drive source-evidence review rather than hardcoded keyword rules.
