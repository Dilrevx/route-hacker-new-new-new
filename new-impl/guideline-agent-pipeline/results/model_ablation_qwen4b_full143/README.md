# Qwen3-Embedding-4B Full Unified V2 143-Case Recall Run

This directory records the full frozen Unified V2 paper-eval recall-rank run for `Qwen3-Embedding-4B`. It extends the first-30 model-size ablation in `../model_ablation_qwen_size_30/` to all 143 paper-eval cases.

## Dataset And Fixed Protocol

- Dataset receipt: `new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json`
- Case source: `new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl`
- Case subset: all 143 identities from the frozen Unified V2 paper-eval allowlist
- Identity file SHA256: `e00a8622f2321ea86248de87a2cbbf89b388798e6e6a0d9df6bfbaf69191b805`
- Ranking protocol: `--selection all --limit 1 --case-workers 1 --embedding-backend sentence-transformers --top-k 50000`
- Backend: direct local `sentence-transformers` on `bobo5090`
- Model path: `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-4B`
- Metric: best known vulnerable anchor rank within the saved full candidate ranking; lower is better. Hit@K counts cases whose best known anchor rank is at most K.

## Result Summary

The run completed all 143 cases with no failed output directories. Four cases did not recover a known vulnerable anchor within the saved top-50,000 ranking.

| Embedding model | Completed | Full-rank hits | Misses | p50 rank | p90 rank | p95 rank | p99 rank | Hit@100 | Hit@200 | Hit@500 | Hit@1000 | Hit@5000 | Hit@10000 | Hit@50000 | MRR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3-Embedding-4B | 143/143 | 139/143 | 4/143 | 166 | 3,594 | 5,073 | 12,100 | 55/143 | 74/143 | 94/143 | 109/143 | 132/143 | 137/143 | 139/143 | 0.050733 |

Candidate volume: 1,095,817 candidate anchors over 143 cases, mean 7,663.1 candidates per case.

## P3C64 Query-Residual Diagnostic

A later P3C64 query-residual run is stored in
`../p3c64-full143-top200-20260820/`, but that run is not a valid same-143 A/B
comparison with this Qwen3-Embedding-4B baseline.

The Qwen3-Embedding-4B run used the frozen paper-eval identity file
`paper_eval_143_identities.jsonl` with SHA256
`e00a8622f2321ea86248de87a2cbbf89b388798e6e6a0d9df6bfbaf69191b805`.
The P3C64 run used `--selection all --limit 143` without `--identity-file`,
which selected the first 143 accepted cases from `new_unified_cases.v1.jsonl`.
The two sets overlap on only 38 identities.

On those 38 overlapping identities, candidate counts match exactly and the
comparable result is:

| Metric | Qwen3-Embedding-4B | P3C64 query-residual | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 7/38 | 12/38 | +5 |
| Hit@50 | 10/38 | 15/38 | +5 |
| Hit@100 | 18/38 | 19/38 | +1 |
| Hit@200 | 22/38 | 21/38 | -1 |
| MRR | 0.032255 | 0.071632 | +0.039376 |

Interpretation: the existing P3C64 artifact shows stronger early-rank
concentration on the overlap, but it cannot establish the intended full-143
`+10%` target. Rerun P3C64 with the same frozen `paper_eval_143_identities.jsonl`
identity file before reporting full-set deltas.

## Misses And Tail Cases

Cases without a known vulnerable anchor inside the saved top-50,000 ranking:

| Idx | Identity | Candidates | HCVR type |
| ---: | --- | ---: | --- |
| 40 | `corewcf__corewcf::CVE-2026-54778` | 390 | `concurrent_object_lifecycle` |
| 100 | `steeltoeoss__steeltoe::CVE-2026-50267` | 28 | `file_permission_temp_resource` |
| 106 | `swagger-api__swagger-codegen::CVE-2021-21364` | 17,843 | `file_permission_temp_resource` |
| 121 | `yafnet__yafnet::CVE-2026-43937` | 720 | `m9_wave2` |

Deepest recovered known-anchor ranks:

| Idx | Rank | Identity | Candidates | HCVR type |
| ---: | ---: | --- | ---: | --- |
| 88 | 13,039 | `quarkusio__quarkus::CVE-2025-49574` | 38,444 | `concurrent_object_lifecycle` |
| 141 | 12,100 | `xwiki__xwiki_platform::CVE-2022-23621` | 30,736 | `authorization_bypass` |
| 28 | 8,308 | `apache__tomcat::CVE-2025-52520` | 18,254 | `iris` |
| 107 | 6,760 | `sylius__sylius::CVE-2026-53637` | 11,114 | `business_state_precondition` |
| 20 | 6,112 | `apache__jackrabbit::CVE-2025-53689` | 14,077 | `iris` |

## Reproduction Entry

Remote run base:

```text
/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-143-qwen4b-20260819T052314
```

Launcher:

```text
/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-143-qwen4b-20260819T052314/run_qwen4b_143.sh
```

The launcher used six workers on GPUs `0,2,3,5,6,7`, avoided historically crowded GPU4, set `--embedding-batch-size 128`, and saved `--top-k 50000`.

Wall-clock window from status log:

```text
2026-08-19T07:31:43+08:00..2026-08-19T10:35:06+08:00
```

Aggregation command:

```bash
RUN_BASE=/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-143-qwen4b-20260819T052314 \
OUT_ROOT_NAME=direct-qwen3-4b-top50000 \
MODEL_PATH=/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-4B \
MODEL_LABEL=Qwen3-Embedding-4B \
BACKEND_LABEL="sentence-transformers direct" \
REPORT_TITLE="Qwen3-Embedding-4B Full 143-Case Unified V2 Recall Rank Probe" \
WALL_APPROX="2026-08-19T07:31:43+08:00..2026-08-19T10:35:06+08:00" \
AGG_NAME=aggregate-qwen3-4b-full143 \
IDENTITY_FILE=paper_eval_143_identities.jsonl \
INDEX_WIDTH=3 \
DATASET_LABEL="frozen Unified V2 paper-eval 143 identities from paper_eval_143_identities.jsonl" \
python3 /data/lhq/workspace/hcvr-embedding-qwen-size-runs/aggregate_hcvr_embedding_30.py
```

## Artifact Layout

- `qwen3_embedding_4b/metrics.json`: aggregate metrics.
- `qwen3_embedding_4b/case_rank_table.jsonl`: per-case rank table.
- `qwen3_embedding_4b/report.md`: human-readable report.

The merged full `recall_results.merged.jsonl` is intentionally not committed because it is 387 MB. It remains on `bobo5090` at:

```text
/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-143-qwen4b-20260819T052314/aggregate-qwen3-4b-full143/recall_results.merged.jsonl
```

## Artifact SHA256

| Artifact | SHA256 |
| --- | --- |
| `qwen3_embedding_4b/metrics.json` | `0b9365ed37a271b844f903af20a29e3d2971af41784e14ae8cce5f14463084d1` |
| `qwen3_embedding_4b/case_rank_table.jsonl` | `69200184d194697f6092e5efb8f8642e59a08ee6e6f270de20aacfad4dd58f0b` |
| `qwen3_embedding_4b/report.md` | `e6cd673640aed646e97fa97511dbb03810dd72eec52a4f5638c571e7e5f79a57` |
| remote `recall_results.merged.jsonl` | `911497b3fa65529dab6b1027a511a412e8fe4f4439b82c19abf6a2ecaf699b8a` |

## Operational Notes

- Earlier HTTP/tunnel embedding endpoints on ports `8001` and `8011` appeared to stall, so this full run used direct local `sentence-transformers` loading on `bobo5090`.
- No failed output directories were produced in this full run.
- The longest tail cases were OpenClaw and XWiki repositories. The final case completed at `2026-08-19T10:35:06+08:00`.
