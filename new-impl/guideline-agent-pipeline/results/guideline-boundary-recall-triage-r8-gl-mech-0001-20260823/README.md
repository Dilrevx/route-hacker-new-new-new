# Guideline Boundary Recall Triage

This report joins source-reviewed guideline boundary ledger rows with optional recall rank tables.
It separates semantic boundary quality from retrieval performance so bad cases can drive investigation without becoming hardcoded routing.

## Summary

- Boundaries: 1
- Rank tables: r7-p3c64, old-p3c64, qwen4b
- Primary budget: Top-100
- Semantic statuses: {'source_reviewed_promotable': 1}
- Next actions: {'run_same_identity_recall_for_this_boundary_before_claiming_embedding_effect': 1}

## Boundary Rows

| Guideline | Boundary | Semantic Status | Representatives | Recall Status | Next Action |
| --- | --- | --- | ---: | --- | --- |
| `gl_mech_0001` | `candidate_boundary_01` | `source_reviewed_promotable` | 3 | {"old-p3c64": "recall_coverage_gap", "qwen4b": "recall_coverage_gap", "r7-p3c64": "recall_coverage_gap"} | `run_same_identity_recall_for_this_boundary_before_claiming_embedding_effect` |

## Case Recall Details

### gl_mech_0001 / candidate_boundary_01

| Identity | Rank Table | Present | Rank | Primary Hit |
| --- | --- | --- | ---: | --- |
| `centic9__jgit-cookbook::CVE-2022-4817` | `r7-p3c64` | False | n/a | False |
| `centic9__jgit-cookbook::CVE-2022-4817` | `old-p3c64` | False | n/a | False |
| `centic9__jgit-cookbook::CVE-2022-4817` | `qwen4b` | False | n/a | False |
| `devent__globalpom-utils::CVE-2018-25068` | `r7-p3c64` | False | n/a | False |
| `devent__globalpom-utils::CVE-2018-25068` | `old-p3c64` | False | n/a | False |
| `devent__globalpom-utils::CVE-2018-25068` | `qwen4b` | False | n/a | False |
| `openkm__document-management-system::CVE-2022-3969` | `r7-p3c64` | False | n/a | False |
| `openkm__document-management-system::CVE-2022-3969` | `old-p3c64` | False | n/a | False |
| `openkm__document-management-system::CVE-2022-3969` | `qwen4b` | False | n/a | False |

## Policy

- Source-reviewed guideline boundaries and embedding recall evidence are separate axes.
- Bad recall cases can motivate query, slicing, embedding, or ranking investigation, but they are not per-case guideline fixes.
- A promotable boundary is semantically ready only; it becomes recall-proven only after same-identity rank evidence covers its representative cases.
- This report does not update released guidelines, sidecars, rank tables, or audit prompts.
