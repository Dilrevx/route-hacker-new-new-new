# Guideline-v2 r7 Full-143 P3C64 Recall

This directory records a same-identity full-paper-eval rerun for the
evidence-gated r7 guideline sidecar.

## Boundary

- Date: 2026-08-23.
- Dataset: Unified V2 paper-eval 143-case identity allowlist.
- Cases: 143/143 completed.
- Failed/missing: 0.
- Candidate anchors: 1,094,013.
- Mean candidates / case: 7,650.44.
- Embedding backend: `p3c64-query-residual`.
- Base model: `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B`.
- P3C64 state:
  `/data/lhq/workspace/p3-hard-competition-query-adapter-v1/selection_run_v1/p3c64_state.pt`.
- P3C64 state SHA256:
  `5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16`.
- Guideline sidecar:
  `mechanism-guideline-preview-v2-cluster-scope-r7-evidence-gated-20260823/guideline_overrides.jsonl`.
- Guideline mode: `override`.
- Same-identity comparison baseline:
  `results/p3c64-fixed143-paper-eval-20260820/`.
- Remote run root:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-r7-p3c64-full143-20260823T061800`.

The run reused the old full143 source snapshots through symlinks, so candidate
counts match the old P3C64 baseline exactly. The full `recall_results.jsonl`
is intentionally not committed because it is a large per-anchor ranking file.
Its remote path and SHA256 are:

```text
/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-r7-p3c64-full143-20260823T061800/merged/recall_results.jsonl
b7912d207d7c098ab0dcf6f874ea0c118b08ca959b365ff24ededa63f2287410
```

## Full-143 Hit@K

| K | Hit Count | Rate |
| ---: | ---: | ---: |
| 30 | 47 | 0.3287 |
| 50 | 58 | 0.4056 |
| 100 | 76 | 0.5315 |
| 150 | 85 | 0.5944 |
| 200 | 87 | 0.6084 |
| 300 | 96 | 0.6713 |
| 500 | 106 | 0.7413 |

MRR is `0.097064`.

## Same-Identity A/B Against Old P3C64

| Budget | Old P3C64 | r7 evidence-gated override | Delta |
| --- | ---: | ---: | ---: |
| Top-30 | 45/143 = 0.3147 | 47/143 = 0.3287 | +2 cases / +1.4 pp |
| Top-50 | 56/143 = 0.3916 | 58/143 = 0.4056 | +2 cases / +1.4 pp |
| Top-100 | 73/143 = 0.5105 | 76/143 = 0.5315 | +3 cases / +2.1 pp |
| Top-150 | 83/143 = 0.5804 | 85/143 = 0.5944 | +2 cases / +1.4 pp |
| Top-200 | 84/143 = 0.5874 | 87/143 = 0.6084 | +3 cases / +2.1 pp |
| Top-300 | 91/143 = 0.6364 | 96/143 = 0.6713 | +5 cases / +3.5 pp |
| Top-500 | 103/143 = 0.7203 | 106/143 = 0.7413 | +3 cases / +2.1 pp |

Top-100 crossing:

- Both hit: 72.
- r7-only hit: 4.
- old-only hit: 1.
- Both miss: 66.

r7-only Top-100 gains:

- `keycloak__keycloak::CVE-2022-4361`: rank 2524 -> 25.
- `xwiki__xwiki-commons::CVE-2024-31996`: rank 150 -> 40.
- `useplunk__plunk::CVE-2026-32096`: rank 106 -> 43.
- `xwiki__xwiki-rendering::CVE-2025-66474`: rank 248 -> 71.

Old-only Top-100 regression:

- `code16__sharp::CVE-2026-53634`: rank 74 -> 104.

## Override-Covered Diagnostic Subset

The r7 sidecar covers 28 of the 143 paper-eval identities. A same-identity
diagnostic run over only those 28 covered cases is stored remotely at:

```text
/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-r7-p3c64-override-covered28-20260823T051900
```

On this covered subset, r7 improves old P3C64 from `12/28` to `16/28` at
Top-100 and from `15/28` to `18/28` at Top-200. This is useful diagnostic
evidence that the rewritten guidelines can improve recall where they apply, but
the paper-facing aggregate claim should use the full143 table above.

## Interpretation

This run supports a conservative conclusion: r7 guideline generation improves
the existing P3C64 retrieval path slightly on the full 143-case paper-eval
identity set while producing stronger gains on the subset where r7 actually
overrides the old guideline text. It does not support a new `+10 pp` full143
claim over old P3C64. The larger `+10 pp` claim remains the P3C64-vs-Qwen4B
model comparison documented in `../p3c64-fixed143-paper-eval-20260820/`.

TraeX LLM-as-a-judge should be used as semantic guideline review evidence:
whether a guideline describes a reusable mechanism with coherent source, sink,
missing guard, and fix semantics. It should not score embedding rank, known
anchor hit, or Top-K recall, and it should not become a hidden rule-based answer
key. Paper claims should keep three evidence lines separate: structural
sanity/purity diagnostics, LLM semantic review, and same-identity embedding
recall.

## Local Artifacts

- `summary.json`: merged r7 full143 metrics.
- `old_p3c64_comparison.md` / `old_p3c64_comparison.json`: same-identity A/B
  against the old P3C64 baseline.
- `r7_case_rank_table.jsonl`: one compact row per case with best known-anchor
  rank and Top-1 anchor metadata.
- `selected_cases.jsonl`: Top-1 recalled anchor per case for downstream audit.
- `snapshot_link_report.json`: snapshot reuse report.
