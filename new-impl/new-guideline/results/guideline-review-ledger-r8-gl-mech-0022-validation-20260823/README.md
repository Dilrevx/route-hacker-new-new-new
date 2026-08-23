# Guideline Review Ledger Validation

This report validates filled reviewer ledger rows before any guideline promotion.
It is a gate report only and does not update released guideline artifacts.

## Summary

- Rows: 4
- Valid rows: 4
- Invalid rows: 0
- Promotable rows: 1
- Decisions: {'needs_more_evidence': 2, 'promote_boundary': 1, 'split_further': 1}

## Rows

| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `gl_mech_0022` | `candidate_boundary_01` | `promote_boundary` | True | n/a | n/a |
| 2 | `gl_mech_0022` | `candidate_boundary_04` | `split_further` | True | n/a | n/a |
| 3 | `gl_mech_0022` | `candidate_boundary_01.aws_amplify_pending` | `needs_more_evidence` | True | n/a | n/a |
| 4 | `gl_mech_0022` | `candidate_boundary_01.bonita_pending` | `needs_more_evidence` | True | n/a | n/a |

## Use Policy

- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.
- It does not mean the recall effect is known.
- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.
