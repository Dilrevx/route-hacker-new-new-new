# Guideline Review Ledger Validation

This report validates filled reviewer ledger rows before any guideline promotion.
It is a gate report only and does not update released guideline artifacts.

## Summary

- Rows: 4
- Valid rows: 4
- Invalid rows: 0
- Promotable rows: 3
- Decisions: {'mark_out_of_scope': 1, 'promote_boundary': 3}

## Rows

| Line | Guideline | Boundary | Decision | Valid | Errors | Warnings |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `review_mech_0017` | `candidate_boundary_01_static_resource_path_containment` | `promote_boundary` | True | n/a | n/a |
| 2 | `review_mech_0017` | `candidate_boundary_02_multipart_original_filename_write` | `promote_boundary` | True | n/a | n/a |
| 3 | `review_mech_0017` | `candidate_boundary_03_recursive_copy_move_ancestor_guard` | `promote_boundary` | True | n/a | n/a |
| 4 | `review_mech_0017` | `candidate_boundary_04_cuba_upload_size_out_of_scope` | `mark_out_of_scope` | True | n/a | n/a |

## Use Policy

- `promote_boundary` means the semantic evidence is complete enough for a proposed guideline edit.
- It does not mean the recall effect is known.
- After changing recall-consumed sidecar text, run same-identity recall before reporting any retrieval claim.
