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
| Design reusable guideline classification that generalizes across CVEs but remains audit-specific. | `partially_satisfied_needs_evidence` | mechanism guideline generator uses offline mechanism attribution, member evidence support, release-ready gating, and review queue quarantine<br>weighted_primary_hcvr_purity=0.8659376811594203<br>weighted_cwe_purity=0.9245177536231884<br>judge_decision_counts={'accept': 2, 'needs_evidence': 10, 'revise': 5, 'split': 3}<br>evidence_worklist_actions={'collect_source_sink_guard_evidence': 10, 'keep_as_control_group': 2, 'revise_mechanism_text_from_evidence': 5, 'split_mechanism_boundary': 3}<br>source_reviewed_boundary_status=partially_satisfied_source_reviewed_boundaries_need_judge_or_revision<br>source_reviewed_boundary_validation_decisions={'needs_more_evidence': 9, 'promote_boundary': 17, 'split_further': 2}<br>source_reviewed_boundary_judge_decisions={'accept': 19, 'needs_evidence': 8} | TraeX judge still finds many groups needing source/sink/guard evidence or split/revision work. |
| Cover the semantic evidence worklist before treating guideline classification as complete. | `not_satisfied_source_review_coverage_incomplete` | evidence_coverage_status=not_satisfied_source_review_coverage_incomplete<br>coverage_rows=20/20<br>coverage_status_counts={'not_source_reviewed': 9, 'source_reviewed_and_judge_accepted': 11}<br>coverage_next_action_counts={'fill_source_review_ledger': 7, 'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 11}<br>coverage_blocking_next_action_count=7<br>coverage_recall_followup_count=11<br>source_review_judge_accepted=11/18 | Blocking source-review actions remain before the guideline taxonomy can be treated as semantically covered. |
| Keep guidelines compatible with the tuned embedding recall path. | `compatible_but_improvement_below_target` | recall_status=inherited_same_identity_by_sidecar_equivalence<br>same_identity_set=True<br>same_identity_order=True<br>recall_equivalence_status=valid_consumed_text_equivalence<br>primary_budget=100<br>recall_alignment_joined=28/143<br>recall_alignment_attention_counts={'embedding_or_candidate_recall_attention': 6, 'guideline_quality_attention': 121, 'label_mixed_structural_attention': 8, 'missing_recall_rows': 44}<br>recall_side_debug_group_count=6<br>recall_side_debug_miss_state_totals={'coverage_gap_not_in_rank_table': 9, 'ranked_below_primary_budget': 6}<br>boundary_recall_triage_aligned_boundaries=1<br>boundary_recall_triage_rank_tables=['p3c64-3case'] | The current r8 recall evidence is inherited by unchanged sidecar text; a fresh run is required after any consumed guideline text changes. |
| Use recall bad cases as motivation without turning them into answer keys. | `satisfied_by_current_policy` | known anchors are used after ranking for metrics, not for query construction<br>evidence worklist marks judge/bad-case material as review_only_not_release_not_recall_input<br>README forbids runtime regex fallback, hidden label routing, and per-case fixes | Must be rechecked whenever generator or recall query construction changes. |
| If semantic guideline quality is strong but recall remains weak, inspect recall method before weakening taxonomy. | `satisfied_as_evaluation_policy` | README separates semantic guideline quality from embedding recall compatibility<br>revision backlog has actions for embedding/candidate/query mismatch<br>scorecard separates structural, judge, recall, and sidecar-equivalence evidence<br>source-reviewed boundaries can be marked semantically ready without being counted as recall-proven<br>label_mixture_is_blocking=False<br>min_clean_purity_is_blocking=False<br>recall-side debug pack separates rank misses from rank-table coverage gaps<br>recall_side_miss_inspection_case_count=15<br>recall_side_miss_inspection_states={'coverage_gap_not_in_rank_table': 9, 'ranked_below_primary_budget': 6} | Need per-group semantic-vs-recall triage after the next changed-sidecar recall run. |
| Avoid hardcoding and be cautious with paper-facing engineering combinations. | `satisfied_by_current_policy` | scorecard marks recall improvement claim as not_supported_at_desired_delta<br>RRF/fusion is documented as a recall-compatible engineering path, not a guideline-quality claim<br>TraeX judge output feeds backlog/worklist rather than released guidelines or ranking<br>new embedders, fusion, or rerankers are allowed only as explicit same-identity A/B configurations<br>recall_candidate_pair_anchor_overlap_choice_rate=0.8333333333333334<br>recall_candidate_list_status=coverage_gap_only_not_rerank_hit_evidence<br>recall_candidate_list_denominator=0 | Any future fusion or model substitution needs same-identity A/B and a separate claim boundary. |

## Source-Review Coverage Gate

- Status: `not_satisfied_source_review_coverage_incomplete`
- Coverage rows: 20 / 20
- Coverage statuses: {'not_source_reviewed': 9, 'source_reviewed_and_judge_accepted': 11}
- Next actions: {'fill_source_review_ledger': 7, 'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 11}
- Blocking next actions: 7
- Recall follow-up rows: 11
- Source-review actions accepted by judge: 11 / 18

This gate prevents a partially source-reviewed ledger set from being mistaken for full guideline readiness. It is still a planning artifact only: it does not mutate guideline text, recall sidecars, embedding inputs, ranking outputs, or audit prompts.

## Source-Reviewed Boundary Evidence

- Status: `partially_satisfied_source_reviewed_boundaries_need_judge_or_revision`
- Ledger valid/invalid: 28 / 0
- Promotable boundaries: 17
- Ledger decisions: {'needs_more_evidence': 9, 'promote_boundary': 17, 'split_further': 2}
- Judge decisions: {'accept': 19, 'needs_evidence': 8}
- Judge average scores: {'actionability_score': 0.6466666666666667, 'coherence_score': 0.7277777777777777, 'coverage_score': 0.49888888888888894, 'retrieval_query_quality': 0.6477777777777777}

This section records source-reviewed guideline-boundary evidence. It can support a semantic boundary decision, but it does not prove recall. If one of these boundaries misses Top-K, the next action is recall-side diagnosis or a same-identity model/ranking A/B, not automatic taxonomy degradation.

## Recall Alignment Diagnostics

- Status: `provided`
- Recall label: `r7-p3c64-full143`
- Joined recall cases: 28 / 143
- Same identity baseline: True
- Attention counts: {'embedding_or_candidate_recall_attention': 6, 'guideline_quality_attention': 121, 'label_mixed_structural_attention': 8, 'missing_recall_rows': 44}
- Cleanliness policy: {'blocking_flags': ['incomplete_actionability_fields', 'pending_review', 'review_only', 'source_only_no_case_metadata'], 'label_mixed_flags': ['mixed_cwe', 'mixed_hcvr'], 'label_mixture_is_blocking': False, 'min_clean_purity_is_blocking': False, 'rationale': 'Clean-enough means source/sink/guard evidence is release-usable. HCVR/CWE mixture remains a review signal because reusable mechanisms can cross labels.'}

This diagnostic separates clean semantic boundaries from recall misses. Mixed HCVR/CWE labels remain review signals, but they are not hard gates because one reusable mechanism can cut across labels.

## Recall-Side Debug Evidence

- Status: `provided`
- Recall label: `r7-p3c64-full143`
- Debug groups: 6
- Miss states: {'coverage_gap_not_in_rank_table': 9, 'ranked_below_primary_budget': 6}
- Recommended checks: {'compare_embedding_backend_or_query_adapter_on_same_identity': 6, 'inspect_candidate_slicing_for_known_anchor_context': 6, 'inspect_guideline_query_wording_against_source_evidence': 6, 'review_label_mixture_without_treating_it_as_hard_failure': 2, 'verify_identity_filter_dataset_split_and_rank_table_coverage': 3}

These rows are a work queue for recall-side diagnosis. They do not rewrite mechanism taxonomy and do not justify engineering combinations unless a same-identity A/B later supports that claim.

## Recall-Side Case Inspection

- Status: `provided`
- Recall label: `r7-p3c64-full143`
- Cases inspected: 15
- Miss states: {'coverage_gap_not_in_rank_table': 9, 'ranked_below_primary_budget': 6}
- Diagnosis counts: {'identity_absent_from_rank_table': 9, 'known_anchor_present_in_export_but_below_primary_budget': 6, 'known_anchor_ranked_below_primary_budget': 6, 'large_candidate_pool_budget_pressure': 3}
- Next checks: {'compare_embedding_backend_or_query_adapter_on_same_identity': 6, 'inspect_budget_or_reranker_need_on_same_identity': 3, 'inspect_candidate_slicing_for_known_anchor_context': 6, 'inspect_guideline_query_wording_against_source_evidence': 6, 'verify_identity_filter_dataset_split_and_rank_table_coverage': 9}
- Input capability: {'case_alignment_rows': True, 'case_rank_summary_rows': True, 'full_ranked_candidate_lists': True, 'known_anchor_span_details': True}

This is the case-level expansion of the recall-side debug queue with exported Top-N candidate rows. It can show whether known-anchor-overlapping slices are present in the exported budget and whether they are simply ranked below the primary budget; it still does not prove vulnerability precision.

## Recall-Candidate Judge Diagnostics

- Status: `provided`
- Pair judge parsed/missing/invalid: 6 / 0 / 0
- Pair judge outcome counts: {'anchor_overlap_chosen': 5, 'neither': 1}
- Pair judge anchor-overlap choice rate: 0.8333333333333334
- List judge status: `coverage_gap_only_not_rerank_hit_evidence`
- List judge prompts parsed/missing/invalid: 11 / 0 / 2
- List judge identity coverage gaps: 6
- List judge rerank denominator: 0

Candidate judge outputs are useful for deciding whether to try a reranker, wider candidate budget, or query rewrite. They are not recall evidence and they do not change guideline text, sidecars, embeddings, ranking, or audit prompts.

## Required Gates For The Next Round

| Gate | Run When | Pass Condition | Current State |
| --- | --- | --- | --- |
| `semantic_evidence_gate` | before changing released guideline text or lexicon entries | each promoted group has checked source, sink, missing guard, exploit precondition, and fix semantics for representative member cases | not_satisfied_source_review_coverage_incomplete; blocking_next_actions=7; next_actions={'fill_source_review_ledger': 7, 'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 11} |
| `same_identity_recall_gate` | after recall-consumed guideline sidecar text changes | same_identity_set=true and same_identity_order=true against the frozen comparison baseline | not required for r8 equivalence; required for any next changed sidecar |
| `taxonomy_vs_embed_triage_gate` | when a semantically clean group misses Top-K | record whether the miss is caused by guideline wording, candidate slicing, embedding backend, adapter weights, rank fusion, or audit budget | policy exists; 1 source-reviewed boundary/boundaries currently have same-identity recall examples aligned |
| `recall_method_substitution_gate` | when a source-reviewed guideline is coherent but the current embedding recall misses representative cases | compare any replacement embedder, reranker, or fusion method on the same identities, snapshots, candidates, and budgets without regex fallback or label routing | allowed by policy; no paper-facing method substitution claim until same-identity evidence exists |
| `paper_claim_boundary_gate` | before writing results into the paper | semantic judge evidence, source-reviewed boundary evidence, structural diagnostics, sidecar equivalence, recall A/B deltas, and engineering fusion are reported as separate claims | satisfied by current scorecard format, but final paper table still needs fresh numbers if guideline text changes |

## Interpretation

The current r8 line is methodologically cleaner than earlier iterations: unresolved groups are quarantined, TraeX judge output is advisory, and recall evidence is separated from semantic quality. The objective is still not complete because many reviewed groups need source/sink/guard evidence and the r8 recall evidence is inherited through sidecar equivalence rather than a fresh run after changed guideline text.

The next concrete work is therefore evidence collection and mechanism-boundary repair, followed by a fresh same-identity P3C64 recall run only after the recall-consumed sidecar text changes.
