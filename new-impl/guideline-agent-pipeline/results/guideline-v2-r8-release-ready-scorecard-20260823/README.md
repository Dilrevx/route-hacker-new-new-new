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
| Embedding recall | inherited_same_identity_by_sidecar_equivalence | common identities 143 | Recall metrics are inherited from an existing same-identity A/B because the release sidecar is equivalent under recall-consumed identity keys and guideline text. This is not a fresh recall run. |
| Recall sidecar equivalence | valid_consumed_text_equivalence | changed consumed texts 0 | The released sidecar has the same recall-consumed identity keys and guideline text as the measured sidecar. |

## Recall Budget Deltas

Left: `r7-evidence-gated-full143-p3c64`
Right: `old-p3c64-full143-baseline`

| Budget | Left | Right | Delta Cases | Delta Rate |
| ---: | ---: | ---: | ---: | ---: |
| Top-30 | 47 | 45 | 2 | 1.4% |
| Top-50 | 58 | 56 | 2 | 1.4% |
| Top-100 | 76 | 73 | 3 | 2.1% |
| Top-150 | 85 | 83 | 2 | 1.4% |
| Top-200 | 87 | 84 | 3 | 2.1% |
| Top-300 | 96 | 91 | 5 | 3.5% |
| Top-500 | 106 | 103 | 3 | 2.1% |
| MRR | 0.097064 | 0.088528 | 0.008536 | n/a |

## Sidecar Equivalence

- Compared sidecars: `guideline-v2-r7-evidence-gated-sidecar` vs `guideline-v2-r8-release-ready-sidecar`
- Same key set: True
- Changed consumed guideline texts: 0
- Recall-consumed text equivalent: True

This evidence only covers the guideline text passed into retrieval. It does not cover changes to identities, source snapshots, slicing, embedding service, adapter weights, or ranking parameters.

## Claim Boundaries

- `guideline_classification_quality`: supported_as_advisory_diagnostic. Evidence: group structural summary; source-only and pending-review accounting. Caveat: Purity and flags are weak diagnostics; mechanism quality still needs semantic review.
- `semantic_guideline_quality`: supported_as_advisory_diagnostic. Evidence: LLM-as-judge summary. Caveat: Judge outputs rank review priority and cannot be converted into hardcoded routing.
- `embedding_recall_improvement`: not_supported_at_desired_delta. Evidence: none. Caveat: This claim is inherited by sidecar equivalence and still depends on the unchanged identity file, snapshots, candidate slicing, embedding backend, and ranking parameters.

## Policy

- Optimize guideline wording and grouping from source/sink/guard evidence, not from keyword checks.
- Use bad recall cases as regression and motivation data, not as per-case hardcoded fixes.
- Treat recall numbers as evidence for a specific embedding plus guideline/query configuration.
- Require same identity sets for paper-facing recall deltas.

## Interpretation

A recall-improvement claim needs same-identity A/B evidence and should only name budgets whose delta is at least 10.0% when using a percentage-point threshold.
A guideline-classification claim can cite structural and LLM-judge diagnostics, but those diagnostics remain advisory and should drive source-evidence review rather than hardcoded keyword rules.
