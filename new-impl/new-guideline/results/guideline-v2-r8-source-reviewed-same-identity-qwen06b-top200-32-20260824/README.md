# Source-Reviewed Guideline Same-Identity Recall A/B

This directory records a fresh same-identity recall run for the r8
source-reviewed release candidate. It compares the new source-reviewed
guideline sidecar against the older r8 release-ready sidecar while keeping the
case identities, source snapshots, mechanical slicing parameters, embedding
backend, Top-K budget, and rank comparison script fixed.

## Setup

| Field | Value |
| --- | --- |
| Run date | 2026-08-24 |
| Remote workspace | `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/guideline-v2-same-identity-20260824` |
| Code revision | `28a95f832d8c7277bf817fa6a9358e87bc7df978` |
| QA receipt | `new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json` |
| Case count | 32 |
| Source materialization | 32/32 snapshots ready, 0 failures |
| Embedding backend | OpenAI-compatible service at `http://127.0.0.1:8001/v1` |
| Embedding model | `Qwen/Qwen3-Embedding-0.6B` |
| Case workers | 8 |
| Candidate slicing | 80 lines, stride 40 |
| Top-K | 200 |

The run uses real embedding calls. It does not use mock embeddings, fallback
regex routing, hidden label routing, known-anchor query construction, or
per-case hand fixes. Known anchors are consumed only after ranking to compute
Hit@K and MRR.

## Main Result: 32 Source-Reviewed Identities

The 32-case comparison uses the identities emitted by the source-reviewed
release candidate sidecar. The old r8 sidecar has no override row for 4 of
these identities, so those 4 old-run rows use the recall runner's ordinary
dataset/default guideline fallback. Interpret this table as the current
old-release configuration versus the source-reviewed release candidate over
the source-reviewed identity set.

| Metric | Source-reviewed candidate | Old r8 release-ready | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 23/32 = 0.7188 | 16/32 = 0.5000 | +7 cases / +21.9 pp |
| Hit@50 | 24/32 = 0.7500 | 17/32 = 0.5312 | +7 cases / +21.9 pp |
| Hit@100 | 28/32 = 0.8750 | 21/32 = 0.6562 | +7 cases / +21.9 pp |
| Hit@150 | 28/32 = 0.8750 | 23/32 = 0.7188 | +5 cases / +15.6 pp |
| Hit@200 | 29/32 = 0.9062 | 23/32 = 0.7188 | +6 cases / +18.8 pp |
| MRR | 0.262389 | 0.210817 | +0.051571 |

At Top-200, 23 identities are hit by both runs, 6 are hit only by the
source-reviewed candidate, 0 are hit only by the old r8 sidecar, and 3 are
missed by both.

## Strict Sidecar-Text Subset: Common 28

For a stricter old-vs-new sidecar text comparison, remove the 4 identities
missing from the old sidecar:

- `manydesigns__portofino::CVE-2021-29451`
- `nimble-platform__common::CVE-2021-32631`
- `openhab__openhab-webui::CVE-2024-42468`
- `opensolon__solon::CVE-2025-1584`

On the remaining 28 identities where both sides have explicit sidecar
coverage, the source-reviewed candidate still improves recall:

| Metric | Source-reviewed candidate | Old r8 release-ready | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 20/28 = 0.7143 | 14/28 = 0.5000 | +6 cases / +21.4 pp |
| Hit@50 | 21/28 = 0.7500 | 15/28 = 0.5357 | +6 cases / +21.4 pp |
| Hit@100 | 24/28 = 0.8571 | 18/28 = 0.6429 | +6 cases / +21.4 pp |
| Hit@150 | 24/28 = 0.8571 | 20/28 = 0.7143 | +4 cases / +14.3 pp |
| Hit@200 | 25/28 = 0.8929 | 20/28 = 0.7143 | +5 cases / +17.9 pp |
| MRR | 0.256864 | 0.203393 | +0.053471 |

## Cost And Runtime

| Run | Wall time | Cumulative worker time | Code embedding time | Query embedding time | Candidates | Completed | Failed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Old r8 release-ready sidecar | 2139.580 s | 12849.278 s | 12677.998 s | 138.302 s | 161374 | 32 | 0 |
| Source-reviewed candidate | 2127.866 s | 12762.820 s | 12593.914 s | 132.677 s | 161374 | 32 | 0 |

The embedding service response used by this runner does not return token usage,
so this artifact does not claim token counts. Cost is tracked by candidate
count, query count, wall time, and per-stage timing in each `summary.json`.

## Artifacts

- `comparison/source-reviewed-vs-r8-qwen06b-top200-32-comparison.{json,md}`:
  primary 32-case comparison.
- `comparison/source-reviewed-vs-r8-qwen06b-top200-common28-comparison.{json,md}`:
  stricter comparison on identities with explicit old and new sidecar rows.
- `comparison/per_case_rank_delta.{csv,md}`: per-case rank movement and
  Top-200 crossing status.
- `old-r8-release-ready-sidecar/`: raw old-sidecar recall outputs.
- `source-reviewed-release-candidate/`: raw source-reviewed recall outputs.
- `inputs/identity_summary.json`: identity-set caveat and old-sidecar missing
  identities.
- `inputs/prewarm_summary.json`: source snapshot materialization summary.
- `run_commands.sh`: exact sequential commands used on the remote workspace.
