# P3C64 Query-Residual Full Unified V2 143-Case Recall Run

## Summary

- Cases: 143
- Completed: 143
- Failed: 0
- Candidate anchors: 1493018
- Mean candidates / case: 10440.7
- Hit@100: 56/143 = 0.3916
- Hit@200: 71/143 = 0.4965
- Hit@500: 71/143 = 0.4965
- MRR: 0.080642

## Protocol Diagnostic

This run is not a valid same-143 A/B comparison against the frozen
Qwen3-Embedding-4B full-143 run.

The P3C64 launcher used `--selection all --limit 143` without an
`--identity-file`, so `load_selected_cases()` selected the first 143 accepted
cases from `new_unified_cases.v1.jsonl`. The Qwen3-Embedding-4B run used the
frozen paper-eval identity file:

```text
/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-143-qwen4b-20260819T052314/paper_eval_143_identities.jsonl
sha256 e00a8622f2321ea86248de87a2cbbf89b388798e6e6a0d9df6bfbaf69191b805
```

The two 143-case sets overlap on only 38 identities. Therefore the previously
reported aggregate deltas, such as `P3C64 Hit@200 71/143` versus
`Qwen3-Embedding-4B Hit@200 74/143`, should not be used to decide whether
P3C64 achieved the full-set `+10%` target.

On the 38 overlapping identities, where candidate counts match exactly
(`374250` candidates for each run), the comparable result is:

| Metric | Qwen3-Embedding-4B | P3C64 query-residual | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 7/38 | 12/38 | +5 |
| Hit@50 | 10/38 | 15/38 | +5 |
| Hit@100 | 18/38 | 19/38 | +1 |
| Hit@200 | 22/38 | 21/38 | -1 |
| MRR | 0.032255 | 0.071632 | +0.039376 |

The intersection result still shows stronger early-rank concentration, but the
sample is too small and biased to answer the full-143 question. A valid
full-set result requires rerunning P3C64 with the same `paper_eval_143_identities.jsonl`
identity file used by the Qwen3-Embedding-4B baseline.

## Timing

| Stage | Total seconds | Mean seconds / case |
| --- | ---: | ---: |
| `candidate_text_seconds` | 2.845 | 0.020 |
| `code_embedding_seconds` | 8576.437 | 59.975 |
| `guideline_seconds` | 0.000 | 0.000 |
| `query_embedding_seconds` | 7.852 | 0.055 |
| `score_sort_seconds` | 83.735 | 0.586 |
| `slice_seconds` | 109.634 | 0.767 |
| `snapshot_seconds` | 3084.001 | 21.566 |
| `total_seconds` | 11878.306 | 83.065 |


## Provenance

- Run dir: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-143-run/p3c64-full143-top200-20260820T041131`
- Merged recall results: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-143-run/p3c64-full143-top200-20260820T041131/merged_final143/recall_results.jsonl`
- Selected audit anchors: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-143-run/p3c64-full143-top200-20260820T041131/merged_final143/selected_cases.jsonl`
- P3C64 state SHA256: `5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16`
- Merge source counts: `{"fix_failed_3": 2, "fix_linkis": 1, "shard_0": 10, "shard_1": 11, "shard_2": 107, "shard_3": 12}`
- Repaired cases: `apache__linkis::CVE-2022-44645, aws__aws-sdk-java::CVE-2022-31159, backstage__backstage::CVE-2026-32236`

## Artifact SHA256

| Artifact | SHA256 |
| --- | --- |
| `recall_results.jsonl` | `9d89e081f085f8c52cc18f99e103aee240e1d30c427def067f481ca9122a73f3` |
| `selected_cases.jsonl` | `42f87582360823b4e0c9dbb25982fef184adf0a4b5342e4cf232eb175d9121d7` |
| `summary.json` | `71917b222a26740f87c9a2e951ef405ea90b63a5cd1c8093525789bc704e98e1` |
| `README.md` | `c53a62ed64e6a400d8e98b5503f8b784b382232b817a3e538e6b1b67b5cf825a` |
