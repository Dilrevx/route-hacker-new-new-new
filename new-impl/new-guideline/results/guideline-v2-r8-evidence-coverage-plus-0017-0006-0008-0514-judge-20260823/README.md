# Guideline Evidence Coverage Summary

This artifact joins the r8 evidence worklist with filled source-review ledgers, ledger validation rows, and optional TraeX judge summaries.
It is an audit and planning artifact only: it does not update guideline text, sidecars, rank tables, embeddings, or audit prompts.

## Summary

- Worklist rows: 20
- Ledger rows: 40
- Validation rows: 40
- Judge rows: 39
- Coverage statuses: {'not_source_reviewed': 5, 'source_reviewed_and_judge_accepted': 15}
- Next actions: {'fill_source_review_ledger': 3, 'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 15}
- Source-review actions accepted by judge: 15 / 18
- Promotable boundaries accepted by judge: 27 / 27

## Next Review Queue

| Guideline | Status | Next Action | Worklist Action | Valid Promoted | Judge-Accepted Promoted | Evidence Gaps |
| --- | --- | --- | --- | ---: | ---: | --- |
| `review_mech_0509` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | candidate_split_validation,case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect,source_level_trace_evidence |
| `gl_mech_0009` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | assigned_case_examples,case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect |
| `gl_mech_0012` | `not_source_reviewed` | `fill_source_review_ledger` | `collect_source_sink_guard_evidence` | 0 | 0 | assigned_case_examples,case_source_shape,missing_guard,safe_fix_semantics,sink_or_sensitive_effect |
| `gl_mech_0004` | `not_source_reviewed` | `optional_control_source_review` | `keep_as_control_group` | 0 | 0 | control_case_invariant,source_level_trace_evidence |
| `gl_mech_0010` | `not_source_reviewed` | `optional_control_source_review` | `keep_as_control_group` | 0 | 0 | control_case_invariant |

## Use Policy

- Use `next_review_queue.jsonl` to choose the next source-review or judge-pack batch.
- Treat `source_reviewed_validation_only` as needing ledger-level judge if the boundary will be cited as semantic evidence.
- Treat `source_reviewed_and_judge_accepted` as semantic boundary evidence only; it still needs same-identity recall after sidecar changes.
- Do not convert judge decisions, bad-case identities, known anchors, labels, or example file names into hidden query construction or routing rules.
