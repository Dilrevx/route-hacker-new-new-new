# Guideline Dual-Axis Objective Audit

This audit checks the current guideline-v2 state against two coupled goals:

1. produce reusable, semantically accurate CVE-mechanism guidelines for audit;
2. keep those guidelines compatible with the tuned embedding recall path.

It is a completion audit, not a release file and not a recall input.

## Overall Status

- Status: `not_complete`
- Desired recall delta rate: 0.1000
- Decision: Continue guideline-v2 work through evidence collection before rewriting released guidelines. Do not mark the objective complete until semantic evidence improves and any changed sidecar has a fresh same-identity recall evaluation.

## Prompt-To-Artifact Checklist

| Requirement | Status | Evidence | Gap |
| --- | --- | --- | --- |
| Design reusable guideline classification that generalizes across CVEs but remains audit-specific. | `partially_satisfied_needs_evidence` | mechanism guideline generator uses offline mechanism attribution, member evidence support, release-ready gating, and review queue quarantine<br>weighted_primary_hcvr_purity=0.8659376811594203<br>weighted_cwe_purity=0.9245177536231884<br>judge_decision_counts={'accept': 2, 'needs_evidence': 10, 'revise': 5, 'split': 3}<br>evidence_worklist_actions={'collect_source_sink_guard_evidence': 10, 'keep_as_control_group': 2, 'revise_mechanism_text_from_evidence': 5, 'split_mechanism_boundary': 3} | TraeX judge still finds many groups needing source/sink/guard evidence or split/revision work. |
| Keep guidelines compatible with the tuned embedding recall path. | `compatible_but_improvement_below_target` | recall_status=inherited_same_identity_by_sidecar_equivalence<br>same_identity_set=True<br>same_identity_order=True<br>recall_equivalence_status=valid_consumed_text_equivalence<br>primary_budget=100 | The current r8 recall evidence is inherited by unchanged sidecar text; a fresh run is required after any consumed guideline text changes. |
| Use recall bad cases as motivation without turning them into answer keys. | `satisfied_by_current_policy` | known anchors are used after ranking for metrics, not for query construction<br>evidence worklist marks judge/bad-case material as review_only_not_release_not_recall_input<br>README forbids runtime regex fallback, hidden label routing, and per-case fixes | Must be rechecked whenever generator or recall query construction changes. |
| If semantic guideline quality is strong but recall remains weak, inspect recall method before weakening taxonomy. | `satisfied_as_evaluation_policy` | README separates semantic guideline quality from embedding recall compatibility<br>revision backlog has actions for embedding/candidate/query mismatch<br>scorecard separates structural, judge, recall, and sidecar-equivalence evidence | Need per-group semantic-vs-recall triage after the next changed-sidecar recall run. |
| Avoid hardcoding and be cautious with paper-facing engineering combinations. | `satisfied_by_current_policy` | scorecard marks recall improvement claim as not_supported_at_desired_delta<br>RRF/fusion is documented as a recall-compatible engineering path, not a guideline-quality claim<br>TraeX judge output feeds backlog/worklist rather than released guidelines or ranking | Any future fusion or model substitution needs same-identity A/B and a separate claim boundary. |

## Required Gates For The Next Round

| Gate | Run When | Pass Condition | Current State |
| --- | --- | --- | --- |
| `semantic_evidence_gate` | before changing released guideline text or lexicon entries | each promoted group has checked source, sink, missing guard, exploit precondition, and fix semantics for representative member cases | not passed; evidence worklist has outstanding rows |
| `same_identity_recall_gate` | after recall-consumed guideline sidecar text changes | same_identity_set=true and same_identity_order=true against the frozen comparison baseline | not required for r8 equivalence; required for any next changed sidecar |
| `taxonomy_vs_embed_triage_gate` | when a semantically clean group misses Top-K | record whether the miss is caused by guideline wording, candidate slicing, embedding backend, adapter weights, rank fusion, or audit budget | policy exists; needs per-group run after next recall table |
| `paper_claim_boundary_gate` | before writing results into the paper | semantic judge evidence, structural diagnostics, sidecar equivalence, and recall A/B deltas are reported as separate claims | satisfied by current scorecard format, but final paper table still needs fresh numbers if guideline text changes |

## Interpretation

The current r8 line is methodologically cleaner than earlier iterations: unresolved groups are quarantined, TraeX judge output is advisory, and recall evidence is separated from semantic quality. The objective is still not complete because many reviewed groups need source/sink/guard evidence and the r8 recall evidence is inherited through sidecar equivalence rather than a fresh run after changed guideline text.

The next concrete work is therefore evidence collection and mechanism-boundary repair, followed by a fresh same-identity P3C64 recall run only after the recall-consumed sidecar text changes.
