# P3C64 Query-Residual 30-Case Recall Run

This run wires the recovered P3C64 HCVR checkpoint into the mechanical guideline-anchor recall pipeline.
The backend keeps code candidate embeddings as frozen Qwen3-Embedding-0.6B vectors and applies only the P3C64 query-side residual MLP to guideline vectors.

## Provenance

- Dataset: `new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json`
- Remote output: `/data/lhq/workspace/hcvr-ablation-a-30-v2allow-20260818T164555/p3c64-30case-top200-gpu-20260819`
- Historical P3C64 state: `/data/lhq/workspace/p3-hard-competition-query-adapter-v1/selection_run_v1/p3c64_state.pt`
- P3C64 state SHA256: `5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16`
- Base model: `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B`
- Runtime: `CUDA_VISIBLE_DEVICES=0`, `--embedding-device cuda:0`, `--case-workers 2`, `--embedding-batch-size 128`
- Elapsed: `1968.635` seconds

## Command

```bash
CUDA_VISIBLE_DEVICES=0 python3 scripts/recall_guideline_anchors.py \
  --qa ../hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --output-dir /data/lhq/workspace/hcvr-ablation-a-30-v2allow-20260818T164555/p3c64-30case-top200-gpu-20260819 \
  --repo-cache /data/lhq/workspace/hcvr-ablation-a-30-v2allow-20260818T164555/repo-cache \
  --snapshot-root /data/lhq/workspace/hcvr-ablation-a-30-v2allow-20260818T164555/snapshots \
  --selection all \
  --limit 30 \
  --top-k 200 \
  --audit-anchor-rank 1 \
  --case-workers 2 \
  --embedding-backend p3c64-query-residual \
  --embedding-model /data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B \
  --embedding-device cuda:0 \
  --embedding-batch-size 128 \
  --max-seq-length 512 \
  --p3c64-state /data/lhq/workspace/p3-hard-competition-query-adapter-v1/selection_run_v1/p3c64_state.pt
```

## Metrics

| Metric | Value |
| --- | ---: |
| Cases completed | `30/30` |
| Failed | `0` |
| Candidates | `357914` |
| Mean candidates / case | `11930.47` |
| MRR | `0.1947` |
| Hit@1 | `0.1333` |
| Hit@3 | `0.2333` |
| Hit@10 | `0.2667` |
| Hit@30 | `0.4667` |
| Hit@50 | `0.5000` |
| Hit@100 | `0.5667` |
| Hit@200 | `0.6333` |

## Same-30 Baseline Comparison

The available same-30 frozen-Qwen 0.6B baseline came from `remote-per-case-recall/01..30` in the same remote workspace.

| Metric | Frozen Qwen 0.6B | P3C64 | Absolute Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | `3/30 = 0.1000` | `14/30 = 0.4667` | `+0.3667` |
| Hit@100 | `5/30 = 0.1667` | `17/30 = 0.5667` | `+0.4000` |
| Hit@200 | `9/30 = 0.3000` | `19/30 = 0.6333` | `+0.3333` |
| MRR | `0.0295` | `0.1947` | `+0.1652` |

## Historical P4 Evidence

The recovered P3C64 artifact also includes the original P4 external one-shot result under `/data/lhq/workspace/p3-hard-competition-query-adapter-v1/p4_external_b0_vs_p3c64_one_shot_v1`:

| Metric | B0 | P3C64 |
| --- | ---: | ---: |
| Hit@30 | `0.0476` | `0.2381` |
| Hit@100 | `0.0952` | `0.4762` |
| Hit@200 | `0.1905` | `0.5714` |
| Hit@500 | `0.3810` | `0.7619` |
| First-hit p50 | `887` | `121` |

## Notes

- This is retrieval/known-anchor recall only, not vulnerability confirmation.
- Known anchors are used only after ranking for metric computation.
- The P3C64 method differs from the previously tested `hcvr-dual-lora` checkpoint; it is a query-only residual adapter over frozen code embeddings.
