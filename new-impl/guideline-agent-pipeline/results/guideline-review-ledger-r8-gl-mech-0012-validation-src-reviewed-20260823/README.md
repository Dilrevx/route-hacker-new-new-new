# Guideline Review Ledger Validation

This report validates filled reviewer ledger rows before any guideline promotion.
It is a gate report only and does not update released guideline artifacts.

## Summary

- Rows: 2
- Valid rows: 2
- Invalid rows: 0
- Promotable rows: 1
- Decisions: {'needs_more_evidence': 1, 'promote_boundary': 1}

## Rows

| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `gl_mech_0012` | `candidate_boundary_01_lollms_social_content_stored_xss` | `promote_boundary` | True | n/a | n/a |
| 2 | `gl_mech_0012` | `candidate_boundary_02_lollms_from_dict_needs_patch_evidence` | `needs_more_evidence` | True | n/a | n/a |

## Use Policy

- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.
- It does not mean the recall effect is known.
- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.
