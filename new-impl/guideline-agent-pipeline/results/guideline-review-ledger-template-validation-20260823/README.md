# Guideline Review Ledger Validation

This report validates filled reviewer ledger rows before any guideline promotion.
It is a gate report only and does not update released guideline artifacts.

## Summary

- Rows: 1
- Valid rows: 1
- Invalid rows: 0
- Promotable rows: 0
- Decisions: {'needs_more_evidence': 1}

## Rows

| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `gl_mech_0001` | `candidate_boundary_01` | `needs_more_evidence` | True | n/a | n/a |

## Use Policy

- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.
- It does not mean the recall effect is known.
- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.
