# Guideline-v2 Bad-Case Regression

This run checks whether the cluster-scoped mechanism guideline sidecar improves old P3C64 Top-100 misses.

Scope:

- Cohort: 12 old P3C64 Top-100 misses that are covered by the guideline-v2 sidecar.
- Comparison: same identity keys, same P3C64 query-residual backend, old guideline text versus guideline-v2 sidecar text.
- Retrieval: mechanical source slicing, P3C64 over frozen Qwen3-Embedding-0.6B code vectors, Top-50000 retained for rank measurement.
- Remote full result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-guideline-v2-badcase30-20260821T0505/v2-covered12-linked-gpu6-20260821T052727/`.
- Full `recall_results.jsonl` is kept on `bobo5090` because it is about 48 MB; this directory stores the compact summary, selected rank-1 anchors, and rank comparison table.

Run configuration:

- `embedding_backend`: `p3c64-query-residual`
- Base model: `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B`
- P3C64 state: `/data/lhq/workspace/p3-hard-competition-query-adapter-v1/selection_run_v1/p3c64_state.pt`
- P3C64 state SHA256: `5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16`
- `case_workers`: 1
- `embedding_batch_size`: 32
- `guideline_override_count`: 12
- Elapsed: 950.628 seconds

## Result

| Metric | Old P3C64 | Guideline-v2 |
| --- | ---: | ---: |
| Top-100 hit | 0/12 | 5/12 |
| Top-200 hit | 2/12 | 6/12 |
| Rank improved | - | 8/12 |
| Rank worsened | - | 3/12 |
| Still no known-anchor hit | 1/12 | 1/12 |

## Per-Case Rank

| Case | Old rank | New rank | Delta | Status |
| --- | ---: | ---: | ---: | --- |
| `apache__axis-axis1-java::CVE-2023-51441` | 2729 | 134 | +2595 | improved into Top-200 |
| `apolloconfig__apollo::CVE-2024-43397` | 554 | 751 | -197 | worsened |
| `jeecgboot__jeecgboot::CVE-2025-14908` | 445 | 273 | +172 | improved but still outside Top-200 |
| `jeecgboot__jeecgboot::CVE-2026-5616` | 1002 | 525 | +477 | improved but still outside Top-200 |
| `keycloak__keycloak::CVE-2022-4361` | 2524 | 2 | +2522 | recovered into Top-10 |
| `mezz__justenoughitems::CVE-2024-41565` | 128 | 36 | +92 | recovered into Top-100 |
| `sanluan__publiccms::CVE-2026-2010` | 255 | 94 | +161 | recovered into Top-100 |
| `swagger-api__swagger-codegen::CVE-2021-21363` | 276 | 317 | -41 | worsened |
| `swagger-api__swagger-codegen::CVE-2021-21364` | None | None | n/a | still no hit |
| `xwiki__xwiki-commons::CVE-2024-31996` | 150 | 42 | +108 | recovered into Top-100 |
| `xwiki__xwiki-rendering::CVE-2025-66474` | 248 | 93 | +155 | recovered into Top-100 |
| `xwiki__xwiki_platform::CVE-2022-23621` | 3671 | 5865 | -2194 | worsened |

## Interpretation

The guideline-v2 sidecar has useful signal but is not ready to replace the old query path globally without another iteration.

The strongest gains are mechanism-specific cases such as Keycloak redirect SSRF, XWiki template/eval, PublicCMS scoped authorization, and JEI slot validation. The regressions point to two specific guideline-generation issues:

- `apolloconfig__apollo::CVE-2024-43397` was attributed to missing authentication, while the anchor is a namespace/environment scoped authorization binding check in `ItemController.update`.
- `swagger-api__swagger-codegen::CVE-2021-21363` needs a temporary file/directory create-delete-mkdir race mechanism, not the broad mutable-object TOCTOU guideline.
- `xwiki__xwiki_platform::CVE-2022-23621` is better treated as privileged template/servlet capability exposure or a call-context case; the local anchor does not look like a straightforward authentication-check location.

Recommended next step: refine the mechanism lexicon and guideline text before a full 143-case rerun. Do not retrain P3C64 until guideline wording has stabilized.
