# Guideline Review Ledger Validation

This report validates filled reviewer ledger rows before any guideline promotion.
It is a gate report only and does not update released guideline artifacts.

## Summary

- Rows: 5
- Valid rows: 5
- Invalid rows: 0
- Promotable rows: 4
- Decisions: {'needs_more_evidence': 1, 'promote_boundary': 4}

## Rows

| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `review_mech_0514` | `candidate_boundary_01_inactive_identifier_authentication_acceptance` | `promote_boundary` | True | n/a | n/a |
| 2 | `review_mech_0514` | `candidate_boundary_02_missing_media_token_filter_rejection` | `promote_boundary` | True | n/a | n/a |
| 3 | `review_mech_0514` | `candidate_boundary_03_nonempty_token_without_validation` | `promote_boundary` | True | n/a | n/a |
| 4 | `review_mech_0514` | `candidate_boundary_04_empty_token_scope_authorization_bypass` | `promote_boundary` | True | n/a | n/a |
| 5 | `review_mech_0514` | `candidate_boundary_05_remaining_unreviewed_members` | `needs_more_evidence` | True | n/a | n/a |

## Use Policy

- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.
- It does not mean the recall effect is known.
- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.
