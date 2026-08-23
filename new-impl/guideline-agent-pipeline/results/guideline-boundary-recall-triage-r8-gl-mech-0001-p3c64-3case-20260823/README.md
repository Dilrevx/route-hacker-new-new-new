# Guideline Boundary Recall Triage

This report joins source-reviewed guideline boundary ledger rows with optional recall rank tables.
It separates semantic boundary quality from retrieval performance so bad cases can drive investigation without becoming hardcoded routing.

## Summary

- Boundaries: 1
- Rank tables: p3c64-3case
- Primary budget: Top-200
- Semantic statuses: {'source_reviewed_promotable': 1}
- Next actions: {'semantic_boundary_and_recall_examples_are_aligned_for_next_ablation': 1}

## Boundary Rows

| Guideline | Boundary | Semantic Status | Representatives | Recall Status | Next Action |
| --- | --- | --- | ---: | --- | --- |
| `gl_mech_0001` | `candidate_boundary_01` | `source_reviewed_promotable` | 3 | {"p3c64-3case": "recall_supported_for_boundary_examples"} | `semantic_boundary_and_recall_examples_are_aligned_for_next_ablation` |

## Case Recall Details

### gl_mech_0001 / candidate_boundary_01

| Identity | Rank Table | Present | Rank | Primary Hit |
| --- | --- | --- | ---: | --- |
| `centic9__jgit-cookbook::CVE-2022-4817` | `p3c64-3case` | True | 5 | True |
| `devent__globalpom-utils::CVE-2018-25068` | `p3c64-3case` | True | 1 | True |
| `openkm__document-management-system::CVE-2022-3969` | `p3c64-3case` | True | 27 | True |

## Policy

- Source-reviewed guideline boundaries and embedding recall evidence are separate axes.
- Bad recall cases can motivate query, slicing, embedding, or ranking investigation, but they are not per-case guideline fixes.
- A promotable boundary is semantically ready only; it becomes recall-proven only after same-identity rank evidence covers its representative cases.
- This report does not update released guidelines, sidecars, rank tables, or audit prompts.
