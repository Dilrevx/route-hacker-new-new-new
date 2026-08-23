# Qwen3 Embedding Size Ablation, First 30 Unified V2 Paper-Eval Cases

This directory records the model-size ablation for the guideline anchor recall stage on the first 30 cases of the frozen Unified V2 143-case paper-eval subset. The audit backend replacement experiment is intentionally out of scope here; only the embedding model used by `recall_guideline_anchors.py` is changed.

## Dataset And Fixed Protocol

- Dataset receipt: `new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json`
- Case source: `new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl`
- Case subset: first 30 identities from the frozen 143-case paper-eval allowlist
- Identity file SHA256: `9403df730c7d46dd82b721e0eaf6bf57612d7155d15e3ce704928eb8eedcd613`
- Ranking protocol: `--selection all --limit 1 --case-workers 1 --embedding-backend sentence-transformers --top-k 50000`
- Metric: best known vulnerable anchor rank within the saved full candidate ranking; lower is better. Hit@K counts cases whose best known anchor rank is at most K.
- Candidate volume: 349,262 candidate anchors over 30 cases, mean 11,642.1 candidates per case.

## Results

All rows are complete 30/30 runs under the same protocol. p50/p99 use nearest-rank percentiles over the best known-anchor rank per case.

| Embedding model | Completed | Full-rank hits | p50 rank | p99 rank | Hit@100 | Hit@200 | Hit@500 | Hit@1000 | Hit@5000 | Hit@10000 | MRR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3-Embedding-0.6B | 30/30 | 30/30 | 707 | 13,896 | 5/30 | 9/30 | 13/30 | 16/30 | 23/30 | 27/30 | 0.030183 |
| Qwen3-Embedding-4B | 30/30 | 30/30 | 271 | 8,313 | 10/30 | 14/30 | 17/30 | 20/30 | 28/30 | 30/30 | 0.025628 |
| Qwen3-Embedding-8B | 30/30 | 30/30 | 236 | 11,235 | 12/30 | 14/30 | 17/30 | 19/30 | 26/30 | 29/30 | 0.057730 |

## Interpretation Notes

- 4B improves the median and tail rank substantially over 0.6B on this 30-case slice: p50 707 -> 271, p99 13,896 -> 8,313, Hit@100 5/30 -> 10/30.
- 8B gives the best head recall and MRR in this slice: Hit@100 12/30 and MRR 0.057730. Its p99 tail is worse than 4B on this slice because several known anchors still land deep in the ranking.
- All three models recover every case within the saved `top-k=50000` candidate ranking, so the differences here are ranking quality under realistic audit budgets, not full-rank coverage.

## Artifact Layout

- `qwen3_embedding_0_6b/metrics.json`: aggregate metrics for the 0.6B run.
- `qwen3_embedding_0_6b/case_rank_table.jsonl`: per-case best-rank table for the 0.6B run.
- `qwen3_embedding_0_6b/report.md`: human-readable 0.6B summary.
- `qwen3_embedding_4b/metrics.json`: aggregate metrics for the 4B run.
- `qwen3_embedding_4b/case_rank_table.jsonl`: per-case best-rank table for the 4B run.
- `qwen3_embedding_4b/report.md`: human-readable 4B summary.
- `qwen3_embedding_8b/metrics.json`: aggregate metrics for the 8B run.
- `qwen3_embedding_8b/case_rank_table.jsonl`: per-case best-rank table for the 8B run.
- `qwen3_embedding_8b/report.md`: human-readable 8B summary.

## Reproduction Entry

The completed remote runs were executed on `bobo5090` under:

- 0.6B: `/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-30-20260818T185429`
- 4B: `/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-30-qwen4b-20260818T213016`
- 8B: `/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-30-qwen8b-20260819T041159`

The aggregation helper used for all rows is:

```bash
RUN_BASE=<run-base> \
OUT_ROOT_NAME=<direct-output-dir> \
MODEL_PATH=<absolute-model-path> \
MODEL_LABEL=<model-label> \
AGG_NAME=<aggregate-dir> \
python3 /data/lhq/workspace/hcvr-embedding-qwen-size-runs/aggregate_hcvr_embedding_30.py
```

## Operational Notes

- Earlier HTTP/tunnel embedding endpoints on ports `8001` and `8011` appeared to stall. These completed rows therefore use direct local `sentence-transformers` loading on `bobo5090`, not the tunnel path.
- The initial 4B run used six workers over GPUs 2..7. One worker landed on an already occupied physical GPU and failed cases `03`, `09`, `15`, `21`, and `27` with CUDA OOM.
- Failed 4B attempts left empty output directories. Because `recall_guideline_anchors.py` refuses to overwrite an existing output directory, those empty directories were preserved as `.failed-<timestamp>` and the failed cases were rerun on a free GPU with `--embedding-batch-size 128`.
- `Qwen3-Embedding-8B` was downloaded from ModelScope and passed a CUDA sanity check with embedding dimension 4096. The 30-case run used three workers and `--embedding-batch-size 64` to avoid OOM on 32GB GPUs. The long wall time was dominated by large repository cases such as Tomcat and Camel.
