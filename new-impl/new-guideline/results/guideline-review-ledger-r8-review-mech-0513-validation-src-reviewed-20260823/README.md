# Guideline Review Ledger Validation

This report validates filled reviewer ledger rows before any guideline promotion.
It is a gate report only and does not update released guideline artifacts.

## Summary

- Rows: 4
- Valid rows: 4
- Invalid rows: 0
- Promotable rows: 3
- Decisions: {'needs_more_evidence': 1, 'promote_boundary': 3}

## Rows

| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `review_mech_0513` | `candidate_boundary_01_jjwt_parse_without_jws_verification` | `promote_boundary` | True | n/a | n/a |
| 2 | `review_mech_0513` | `candidate_boundary_02_jose_header_supplied_jwk_trust` | `promote_boundary` | True | n/a | n/a |
| 3 | `review_mech_0513` | `candidate_boundary_03_oidc_none_algorithm_requires_opt_in` | `promote_boundary` | True | n/a | n/a |
| 4 | `review_mech_0513` | `candidate_boundary_04_remaining_unreviewed_members` | `needs_more_evidence` | True | n/a | n/a |

## Use Policy

- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.
- It does not mean the recall effect is known.
- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.
