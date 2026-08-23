# Guideline Evidence Coverage Summary

This artifact joins the r8 evidence worklist with filled source-review ledgers, ledger validation rows, and optional TraeX judge summaries.
It is an audit and planning artifact only: it does not update guideline text, sidecars, rank tables, embeddings, or audit prompts.

## Summary

- Worklist rows: 20
- Ledger rows: 47
- Validation rows: 47
- Judge rows: 46
- Coverage statuses: {'not_source_reviewed': 2, 'source_reviewed_and_judge_accepted': 18}
- Next actions: {'optional_control_source_review': 2, 'run_same_identity_recall_after_sidecar_change': 18}
- Source-review actions accepted by judge: 18 / 18
- Promotable boundaries accepted by judge: 33 / 33

## Next Review Queue

| Guideline | Status | Next Action | Worklist Action | Valid Promoted | Judge-Accepted Promoted | Evidence Gaps |
| --- | --- | --- | --- | ---: | ---: | --- |
| `gl_mech_0004` | `not_source_reviewed` | `optional_control_source_review` | `keep_as_control_group` | 0 | 0 | control_case_invariant,source_level_trace_evidence |
| `gl_mech_0010` | `not_source_reviewed` | `optional_control_source_review` | `keep_as_control_group` | 0 | 0 | control_case_invariant |

## Use Policy

- Use `next_review_queue.jsonl` to choose the next source-review or judge-pack batch.
- Treat `source_reviewed_validation_only` as needing ledger-level judge if the boundary will be cited as semantic evidence.
- Treat `source_reviewed_and_judge_accepted` as semantic boundary evidence only; it still needs same-identity recall after sidecar changes.
- Do not convert judge decisions, bad-case identities, known anchors, labels, or example file names into hidden query construction or routing rules.
