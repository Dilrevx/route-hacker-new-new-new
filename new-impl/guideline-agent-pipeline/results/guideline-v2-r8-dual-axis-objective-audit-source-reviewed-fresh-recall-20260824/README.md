# Guideline Dual-Axis Objective Audit

This audit checks the current guideline-v2 state against two coupled goals:

1. produce reusable, semantically accurate CVE-mechanism guidelines for audit;
2. keep those guidelines compatible with the tuned embedding recall path.

It is a completion audit, not a release file and not a recall input.

## Overall Status

- Status: `complete`
- Desired recall delta rate: 0.1000
- Decision: Objective is covered by current artifacts for this scoped candidate: semantic coverage is source-reviewed, fresh same-identity recall supports the embedding path, and paper-facing claim boundaries remain separated.

## Prompt-To-Artifact Checklist

| Requirement | Status | Evidence | Gap |
| --- | --- | --- | --- |
| Design reusable guideline classification that generalizes across CVEs but remains audit-specific. | `satisfied_by_source_review_coverage` | mechanism guideline generator uses offline mechanism attribution, member evidence support, release-ready gating, and review queue quarantine<br>weighted_primary_hcvr_purity=0.9375<br>weighted_cwe_purity=0.9375<br>judge_decision_counts=None<br>evidence_worklist_actions={'collect_source_sink_guard_evidence': 10, 'keep_as_control_group': 2, 'revise_mechanism_text_from_evidence': 5, 'split_mechanism_boundary': 3}<br>source_reviewed_boundary_status=partially_satisfied_source_reviewed_boundaries_need_judge_or_revision<br>source_reviewed_boundary_validation_decisions={'mark_out_of_scope': 1, 'needs_more_evidence': 11, 'promote_boundary': 33, 'split_further': 2}<br>source_reviewed_boundary_judge_decisions={'accept': 36, 'needs_evidence': 10} | Source-review coverage has no blocking evidence actions for this candidate; remaining semantic evidence caveats are tracked as advisory review signals. |
| Cover the semantic evidence worklist before treating guideline classification as complete. | `satisfied_semantic_coverage_with_recall_evidence` | evidence_coverage_status=satisfied_semantic_coverage_pending_recall_followup<br>coverage_rows=20/20<br>coverage_status_counts={'not_source_reviewed': 2, 'source_reviewed_and_judge_accepted': 18}<br>coverage_next_action_counts={'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 18}<br>coverage_blocking_next_action_count=0<br>coverage_recall_followup_count=18<br>source_review_judge_accepted=18/18 | Semantic coverage is satisfied and the changed sidecar has a valid same-identity recall A/B. |
| Keep guidelines compatible with the tuned embedding recall path. | `satisfied_for_reported_same_identity_budget` | recall_status=valid_same_identity<br>same_identity_set=True<br>same_identity_order=True<br>recall_equivalence_status=missing<br>primary_budget=200<br>recall_alignment_joined=28/143<br>recall_alignment_attention_counts={'embedding_or_candidate_recall_attention': 6, 'guideline_quality_attention': 121, 'label_mixed_structural_attention': 8, 'missing_recall_rows': 44}<br>recall_side_debug_group_count=6<br>recall_side_debug_miss_state_totals={'coverage_gap_not_in_rank_table': 9, 'ranked_below_primary_budget': 6}<br>boundary_recall_triage_aligned_boundaries=1<br>boundary_recall_triage_rank_tables=['p3c64-3case'] | The evaluated guideline/query plus embedding configuration has valid same-identity recall evidence at the reported budget. |
| Use recall bad cases as motivation without turning them into answer keys. | `satisfied_by_current_policy` | known anchors are used after ranking for metrics, not for query construction<br>evidence worklist marks judge/bad-case material as review_only_not_release_not_recall_input<br>README forbids runtime regex fallback, hidden label routing, and per-case fixes | Must be rechecked whenever generator or recall query construction changes. |
| If semantic guideline quality is strong but recall remains weak, inspect recall method before weakening taxonomy. | `satisfied_as_evaluation_policy` | README separates semantic guideline quality from embedding recall compatibility<br>revision backlog has actions for embedding/candidate/query mismatch<br>scorecard separates structural, judge, recall, and sidecar-equivalence evidence<br>source-reviewed boundaries can be marked semantically ready without being counted as recall-proven<br>label_mixture_is_blocking=False<br>min_clean_purity_is_blocking=False<br>recall-side debug pack separates rank misses from rank-table coverage gaps<br>recall_side_miss_inspection_case_count=15<br>recall_side_miss_inspection_states={'coverage_gap_not_in_rank_table': 9, 'ranked_below_primary_budget': 6} | Need per-group semantic-vs-recall triage after the next changed-sidecar recall run. |
| Avoid hardcoding and be cautious with paper-facing engineering combinations. | `satisfied_by_current_policy` | scorecard_recall_claim_status=supported_for_reported_budgets<br>RRF/fusion is documented as a recall-compatible engineering path, not a guideline-quality claim<br>TraeX judge output feeds backlog/worklist rather than released guidelines or ranking<br>new embedders, fusion, or rerankers are allowed only as explicit same-identity A/B configurations<br>recall_candidate_pair_anchor_overlap_choice_rate=0.8333333333333334<br>recall_candidate_list_status=coverage_gap_only_not_rerank_hit_evidence<br>recall_candidate_list_denominator=0 | Any future fusion or model substitution needs same-identity A/B and a separate claim boundary. |

## Source-Review Coverage Gate

- Status: `satisfied_semantic_coverage_pending_recall_followup`
- Coverage rows: 20 / 20
- Coverage statuses: {'not_source_reviewed': 2, 'source_reviewed_and_judge_accepted': 18}
- Next actions: {'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 18}
- Blocking next actions: 0
- Recall follow-up rows: 18
- Source-review actions accepted by judge: 18 / 18

This gate prevents a partially source-reviewed ledger set from being mistaken for full guideline readiness. It is still a planning artifact only: it does not mutate guideline text, recall sidecars, embedding inputs, ranking outputs, or audit prompts.

## Source-Reviewed Boundary Evidence

- Status: `partially_satisfied_source_reviewed_boundaries_need_judge_or_revision`
- Ledger valid/invalid: 47 / 0
- Promotable boundaries: 33
- Ledger decisions: {'mark_out_of_scope': 1, 'needs_more_evidence': 11, 'promote_boundary': 33, 'split_further': 2}
- Judge decisions: {'accept': 36, 'needs_evidence': 10}
- Judge average scores: {'actionability_score': 0.7008695652173912, 'coherence_score': 0.7639130434782608, 'coverage_score': 0.5221739130434784, 'retrieval_query_quality': 0.6873913043478261}

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
| `semantic_evidence_gate` | before changing released guideline text or lexicon entries | each promoted group has checked source, sink, missing guard, exploit precondition, and fix semantics for representative member cases | satisfied_semantic_coverage_pending_recall_followup; blocking_next_actions=0; next_actions={'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 18} |
| `same_identity_recall_gate` | after recall-consumed guideline sidecar text changes | same_identity_set=true and same_identity_order=true against the frozen comparison baseline | satisfied for the current changed sidecar by fresh same-identity recall evidence |
| `taxonomy_vs_embed_triage_gate` | when a semantically clean group misses Top-K | record whether the miss is caused by guideline wording, candidate slicing, embedding backend, adapter weights, rank fusion, or audit budget | policy exists; 1 source-reviewed boundary/boundaries currently have same-identity recall examples aligned |
| `recall_method_substitution_gate` | when a source-reviewed guideline is coherent but the current embedding recall misses representative cases | compare any replacement embedder, reranker, or fusion method on the same identities, snapshots, candidates, and budgets without regex fallback or label routing | allowed by policy; no paper-facing method substitution claim until same-identity evidence exists |
| `paper_claim_boundary_gate` | before writing results into the paper | semantic judge evidence, source-reviewed boundary evidence, structural diagnostics, sidecar equivalence, recall A/B deltas, and engineering fusion are reported as separate claims | satisfied by current scorecard format, but final paper table still needs fresh numbers if guideline text changes |

## Interpretation

The current scoped candidate satisfies the dual-axis gate recorded here: source-review coverage has no blocking evidence action, and the changed recall-consumed sidecar has fresh same-identity recall evidence over the evaluated identities.

Paper text should still separate semantic guideline quality from retrieval performance. This audit supports the evaluated guideline/query plus embedding configuration, not an unconditional claim that the taxonomy is optimal for every future model or dataset split.
