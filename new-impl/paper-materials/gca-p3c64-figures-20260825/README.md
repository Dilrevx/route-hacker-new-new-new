# Paper Material Pack: GCA Case Study and P3C64 Retrieval Figures

Generated on 2026-08-25 from existing `new-impl/new-guideline/results` artifacts.

## Contents

| File | Purpose |
| --- | --- |
| `typical_guideline_case.md` | Paper-ready JNDI guideline case study. |
| `gca_coverage_funnel.svg` | Coverage/headroom visualization for the 143-case paper set. |
| `gca_space_contrast.svg` | One-slide CVE/CWE annotation space vs GCA mechanism space contrast. |
| `gca_cwe_to_mechanisms.svg` | Shows coarse CWE labels splitting into multiple GCA mechanisms. |
| `gca_mechanism_to_cwes.svg` | Shows reusable GCA mechanisms crossing multiple CWE labels. |
| `gca_vs_cwe_notes.md` | Tables and claim boundaries for the GCA figures. |
| `p3c64_hit_at_k.svg` | Same-identity Hit@K comparison between P3C64 and Qwen3-Embedding-4B. |
| `p3c64_rank_shift_examples.svg` | Representative rank shifts where P3C64 brings cases into Top-200. |
| `p3c64_by_type_hit100.svg` | Per-HCVR-type Top-100 comparison for semantic-family discussion. |
| `p3c64_visualization_notes.md` | Tables and claim boundaries for P3C64 figures. |
| `paper_snippets.md` | Short paper-ready paragraphs and captions. |
| `material_summary.json` | Machine-readable summary of the generated material. |
| `generate_materials.py` | Reproducible generator using only Python standard library. |

## Key Numbers

- GCA primary released sidecar coverage: 28 / 143.
- GCA coverage upper bound if all CVE IDs are ingested: 136 / 143.
- P3C64 Hit@100: 73 / 143; Qwen3-Embedding-4B Hit@100: 55 / 143; delta: +18 cases.
- P3C64 Hit@200: 84 / 143; Qwen3-Embedding-4B Hit@200: 74 / 143; delta: +10 cases.
- P3C64-only Top-200 cases: 22; Qwen4B-only Top-200 cases: 12.

## Provenance

- Coverage audit: `new-impl/new-guideline/results/guideline-v2-coverage-audit-full143-20260824/summary.json` and `new-impl/new-guideline/results/guideline-v2-coverage-audit-full143-20260824/case_coverage.jsonl`.
- Guideline sidecar: `new-impl/new-guideline/results/mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/guideline_overrides.jsonl`.
- Mechanism candidates: `new-impl/new-guideline/results/mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/mechanism_candidates.jsonl`.
- Structured CVE join: `/tmp/hcvr_guideline_coverage_audit_20260824/structured_cves_combined.jsonl`.
- P3C64 evaluation: `new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/summary.json` and `new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/p3c64_case_rank_table.jsonl`.
- Qwen4B comparison: `new-impl/new-guideline/results/model_ablation_qwen4b_full143/qwen3_embedding_4b/metrics.json` and `new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/qwen4b_case_rank_table.jsonl`.

## Claim Boundaries

- Use the GCA figures for metadata quality, cluster/mechanism construction, and guideline release coverage. Use separate audit receipts for final audit precision or confirmed vulnerability recall.
- Use the P3C64 figures for same-identity known-anchor retrieval. They support a mechanism-conditioned ranking improvement claim; a direct geometric semantics claim should use saved embedding-vector projections or nearest-neighbor evidence.
- Use the JNDI case study as a guideline example derived from the release-ready sidecar. Pair it with source-level evidence when presenting a full end-to-end case study.
