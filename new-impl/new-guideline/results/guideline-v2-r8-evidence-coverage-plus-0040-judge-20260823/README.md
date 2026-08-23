# Guideline Evidence Coverage Summary

This artifact joins the r8 evidence worklist with filled source-review ledgers, ledger validation rows, and optional TraeX judge summaries.
It is an audit and planning artifact only: it does not update guideline text, sidecars, rank tables, embeddings, or audit prompts.

## Summary

- Worklist rows: 20
- Ledger rows: 24
- Validation rows: 24
- Judge rows: 23
- Coverage statuses: {'not_source_reviewed': 10, 'source_reviewed_and_judge_accepted': 10}
- Next actions: {'fill_source_review_ledger': 8, 'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 10}
- Source-review actions accepted by judge: 10 / 18
- Promotable boundaries accepted by judge: 14 / 14

## Next Review Queue

| Guideline | Status | Next Action | Worklist Action | Valid Promoted | Judge-Accepted Promoted | Evidence Gaps |
| --- | --- | --- | --- | ---: | ---: | --- |
| `review_mech_0017` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | case_source_shape,missing_guard,mixed_membership_boundary,safe_fix_semantics,sink_or_sensitive_effect,source_level_trace_evidence |
| `review_mech_0509` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | candidate_split_validation,case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect,source_level_trace_evidence |
| `review_mech_0513` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect,source_level_trace_evidence |
| `review_mech_0514` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | candidate_split_validation,case_source_shape,missing_guard,mixed_membership_boundary,safe_fix_semantics,sink_or_sensitive_effect,source_level_trace_evidence |
| `gl_mech_0006` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | assigned_case_examples,case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect |
| `gl_mech_0008` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | assigned_case_examples,case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect |
| `gl_mech_0009` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | assigned_case_examples,case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect |
| `gl_mech_0012` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | assigned_case_examples,case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect |
| `gl_mech_0004` | `not_source_reviewed` | `optional_control_source_review` | `keep_as_control_group` | 0 | 0 | control_case_invariant,source_level_trace_evidence |
| `gl_mech_0010` | `not_source_reviewed` | `optional_control_source_review` | `keep_as_control_group` | 0 | 0 | control_case_invariant |

## Use Policy

- Use `next_review_queue.jsonl` to choose the next source-review or judge-pack batch.
- Treat `source_reviewed_validation_only` as needing ledger-level judge if the boundary will be cited as semantic evidence.
- Treat `source_reviewed_and_judge_accepted` as semantic boundary evidence only; it still needs same-identity recall after sidecar changes.
- Do not convert judge decisions, bad-case identities, known anchors, labels, or example file names into hidden query construction or routing rules.
