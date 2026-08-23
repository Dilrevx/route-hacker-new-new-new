# Guideline Review Ledger Validation

This report validates filled reviewer ledger rows before any guideline promotion.
It is a gate report only and does not update released guideline artifacts.

## Summary

- Rows: 6
- Valid rows: 6
- Invalid rows: 0
- Promotable rows: 4
- Decisions: {'needs_more_evidence': 2, 'promote_boundary': 4}

## Rows

| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `gl_mech_0040` | `candidate_boundary_01_template_text_engine_exec` | `promote_boundary` | True | n/a | n/a |
| 2 | `gl_mech_0040` | `candidate_boundary_02_bean_validation_message_el` | `promote_boundary` | True | n/a | n/a |
| 3 | `gl_mech_0040` | `candidate_boundary_02b_parser_error_message_needs_evidence` | `needs_more_evidence` | True | n/a | n/a |
| 4 | `gl_mech_0040` | `candidate_boundary_03_spel_context` | `promote_boundary` | True | n/a | n/a |
| 5 | `gl_mech_0040` | `candidate_boundary_04_jinjava_sandbox_escape` | `promote_boundary` | True | n/a | n/a |
| 6 | `gl_mech_0040` | `candidate_boundary_05_unreviewed_or_distinct_members` | `needs_more_evidence` | True | n/a | n/a |

## Use Policy

- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.
- It does not mean the recall effect is known.
- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.
