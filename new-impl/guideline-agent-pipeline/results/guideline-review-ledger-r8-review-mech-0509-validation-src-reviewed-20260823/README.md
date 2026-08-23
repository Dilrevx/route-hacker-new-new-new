# Guideline Review Ledger Validation

This report validates filled reviewer ledger rows before any guideline promotion.
It is a gate report only and does not update released guideline artifacts.

## Summary

- Rows: 4
- Valid rows: 4
- Invalid rows: 0
- Promotable rows: 4
- Decisions: {'promote_boundary': 4}

## Rows

| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `review_mech_0509` | `candidate_boundary_01_jwt_none_algorithm_default` | `promote_boundary` | True | n/a | n/a |
| 2 | `review_mech_0509` | `candidate_boundary_02_empty_token_callback` | `promote_boundary` | True | n/a | n/a |
| 3 | `review_mech_0509` | `candidate_boundary_03_public_jwt_secret_fallback` | `promote_boundary` | True | n/a | n/a |
| 4 | `review_mech_0509` | `candidate_boundary_04_oidc_session_expiry_binding` | `promote_boundary` | True | n/a | n/a |

## Use Policy

- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.
- It does not mean the recall effect is known.
- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.
