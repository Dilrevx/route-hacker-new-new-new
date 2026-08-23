# HCVR Guideline Experiment Scorecard

- Release: `p3c64-current-guideline-baseline-control`
- Guidelines: 202
- Work items: 326
- Active attributions: 237
- Pending review: 89
- Recall sidecar rows: 153
- Pending overrides included: False

## Evidence Axes

| Axis | Status | Main Evidence | Boundary |
| --- | --- | --- | --- |
| Guideline grouping | advisory_structural_diagnostic | 68 evaluated groups, weighted HCVR purity 0.7568, weighted CWE purity 0.8676 | Structural labels are triage signals for guideline grouping, not hard pass/fail gates. |
| LLM semantic judge | advisory_semantic_diagnostic | parsed 20/20, accepted 0, low-score 18 | LLM-as-judge output is semantic review evidence; it must not become keyword routing or a hidden optimization target. |
| Embedding recall | valid_same_identity | common identities 143 | Recall A/B evidence is valid for retrieval claims because both sides use the same identity set. |

## Recall Budget Deltas

Left: `p3c64-fixed-paper-eval-143`
Right: `qwen3-embedding-4b-frozen-paper-eval`

| Budget | Left | Right | Delta Cases | Delta Rate |
| ---: | ---: | ---: | ---: | ---: |
| Top-30 | 45 | 30 | 15 | 10.5% |
| Top-50 | 56 | 37 | 19 | 13.3% |
| Top-100 | 73 | 55 | 18 | 12.6% |
| Top-200 | 84 | 74 | 10 | 7.0% |
| Top-300 | 91 | 82 | 9 | 6.3% |
| Top-500 | 103 | 94 | 9 | 6.3% |
| MRR | 0.088528 | 0.050733 | 0.037794 | n/a |

## Claim Boundaries

- `guideline_classification_quality`: supported_as_advisory_diagnostic. Evidence: group structural summary; source-only and pending-review accounting. Caveat: Purity and flags are weak diagnostics; mechanism quality still needs semantic review.
- `semantic_guideline_quality`: supported_as_advisory_diagnostic. Evidence: LLM-as-judge summary. Caveat: Judge outputs rank review priority and cannot be converted into hardcoded routing.
- `embedding_recall_improvement`: supported_for_reported_budgets. Evidence: Hit@30 delta 15 cases / 10.5%; Hit@50 delta 19 cases / 13.3%; Hit@100 delta 18 cases / 12.6%. Caveat: This claim is about the evaluated embedding plus guideline/query configuration, not guideline taxonomy quality alone.

## Policy

- Optimize guideline wording and grouping from source/sink/guard evidence, not from keyword checks.
- Use bad recall cases as regression and motivation data, not as per-case hardcoded fixes.
- Treat recall numbers as evidence for a specific embedding plus guideline/query configuration.
- Require same identity sets for paper-facing recall deltas.

## Interpretation

A recall-improvement claim needs same-identity A/B evidence and should only name budgets whose delta is at least 10.0% when using a percentage-point threshold.
A guideline-classification claim can cite structural and LLM-judge diagnostics, but those diagnostics remain advisory and should drive source-evidence review rather than hardcoded keyword rules.
