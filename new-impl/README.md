# Route-Hacker New Implementation

This directory contains the cleaned implementation of the current
guideline-conditioned vulnerability retrieval pipeline.

## Main Pipeline

```text
offline CVE/root-cause clustering
  -> guideline release or guideline sidecar
  -> online repository slicing into candidate anchors
  -> guideline-conditioned embedding recall
  -> Top-K anchor queue
  -> Codex/TraeX audit harness
  -> PoC handoff for instrumentation and dynamic validation
```

The current paper-facing retrieval path lives in
`guideline-agent-pipeline/`. The other directories are support modules for
build/reproduction, audit batching, and runtime PoC verification.

## Current Valid Result

Use this result when discussing the recovered HCVR/P3C64 embedding method on
the Unified V2 paper-eval set:

```text
guideline-agent-pipeline/results/p3c64-fixed143-paper-eval-20260820/
```

It compares P3C64 query-residual retrieval against Qwen3-Embedding-4B on the
same frozen 143 identities.

| Budget | Qwen3-Embedding-4B | P3C64 query-residual | Delta |
| --- | ---: | ---: | ---: |
| Top-30 | 30/143 = 0.2098 | 45/143 = 0.3147 | +15 cases / +10.5 pp |
| Top-50 | 37/143 = 0.2587 | 56/143 = 0.3916 | +19 cases / +13.3 pp |
| Top-100 | 55/143 = 0.3846 | 73/143 = 0.5105 | +18 cases / +12.6 pp |
| Top-150 | 65/143 = 0.4545 | 83/143 = 0.5804 | +18 cases / +12.6 pp |
| Top-200 | 74/143 = 0.5175 | 84/143 = 0.5874 | +10 cases / +7.0 pp |
| Top-300 | 82/143 = 0.5734 | 91/143 = 0.6364 | +9 cases / +6.3 pp |
| Top-500 | 94/143 = 0.6573 | 103/143 = 0.7203 | +9 cases / +6.3 pp |

Recommended paper wording:

- Top-100 and Top-150 support a `>10 percentage-point` recall improvement
  claim.
- Top-200 supports a `+10 recovered cases` claim.
- Do not describe Top-200 as a `+10 percentage-point` gain.

The frozen identity file hash is:

```text
e00a8622f2321ea86248de87a2cbbf89b388798e6e6a0d9df6bfbaf69191b805
```

## Result Files

The valid result directory contains lightweight artifacts that can be committed
and reviewed:

- `README.md`: merged P3C64 Hit@K summary.
- `summary.json`: P3C64 merged run metrics and provenance.
- `qwen4b_comparison.md` / `qwen4b_comparison.json`: same-identity A/B
  comparison against Qwen3-Embedding-4B.
- `p3c64_case_rank_table.jsonl`: one row per case with the P3C64 first known
  anchor rank.
- `qwen4b_case_rank_table.jsonl`: one row per case with the Qwen4B first known
  anchor rank.
- `selected_cases.jsonl`: P3C64 selected Top-1 recalled anchor per case for
  downstream audit smoke runs.
- `paper_eval_143_identities.jsonl`: frozen case identity allowlist.

The full P3C64 `recall_results.jsonl` is 386MB and is not stored in Git. Its
authoritative remote path is:

```text
/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-fixed143-20260820T113743/final_merged/recall_results.jsonl
```

The matching Qwen3-Embedding-4B full result is:

```text
/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-fixed143-20260820T113743/qwen4b_full_recall_merged/recall_results.jsonl
```

## Method Boundary

P3C64 is a query-only residual adapter over Qwen3-Embedding-0.6B. Candidate code
vectors stay frozen; the adapter changes only the guideline/query vector.

Training artifact:

```text
/data/lhq/workspace/p3-hard-competition-query-adapter-v1/selection_run_v1/p3c64_state.pt
sha256 5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16
```

The current 143-case result validates the retrieval improvement under the
current guideline text. It does not yet measure a new guideline-v2 release.

## Guideline-V2 Work

The active bottleneck is guideline quality. The pipeline now supports
mechanism-aware default guideline generation and a non-mutating
`--guideline-file` sidecar.

Use the sidecar path to attach offline clustering output without leaking target
anchors, ranks, file paths, line numbers, or labels into the query text.

Recommended next experiment:

1. Generate mechanism-specific guideline overrides for broad `iris`, `m9_wave*`,
   `m9_expansion`, and fallback cases from allowed offline guideline sources.
2. Rerun P3C64 on the same frozen 143 identity file with `--guideline-file`.
3. Compare against the current P3C64 fixed-143 result using
   `compare_recall_rank_tables.py`.
4. Report Top-100, Top-150, and Top-200 deltas separately.

## Components

- `guideline-agent-pipeline/`: recall, comparison, sharded merge, guideline
  sidecar, audit harness, and result summaries.
- `codex_security_batch/`: Codex/TraeX security audit batching utilities.
- `poc-agent-runner/`: PoC handoff and execution runner.
- `compile-builder-v2/`: source checkout/build support.
- `runtime-v2-verifier-redesign/`: runtime verifier redesign workspace.
- `hcvr_new_unified_dataset_v2/`: local dataset receipt and case metadata.

Start from `guideline-agent-pipeline/README.md` for commands.
