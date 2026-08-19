# HCVR Dual-LoRA 30-Case Guideline Recall

This directory stores the 2026-08-19 30-case recall run that replaces the generic
Qwen3 embedding retriever with the HCVR M1 guideline-anchor dual-LoRA retriever.

## Scope

- Pipeline stage: mechanical source slicing -> guideline-conditioned embedding recall.
- Evaluation signal: known anchor rank, used only after retrieval for statistics.
- No audit, reranker, or PoC verification is included in this result package.

## Model

- Backend: `hcvr-dual-lora`
- Checkpoint: `/data/lhq/workspace/route-hacker/output/guideline_anchor_training_v1/m1_source_release_v1/m1_dual_lora_train_v1`
- Base model override: `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B`
- Base config SHA256 matched the adapter config:
  `b5bf1f51fc45be473a54718cef92448d90a1be001bf9b9a44b8c7f10a19feaa9`

The override is needed because `adapter_config.json` records a stale Hugging Face
cache path, while the available local base model has the same config hash.

## Run

Remote run root:

```bash
/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-30-hcvr-dual-lora-20260819T060913
```

Queue output:

```bash
/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-30-hcvr-dual-lora-20260819T060913/queue-hcvr-dual-lora-top50000-c3
```

Important command arguments:

```bash
--selection all
--limit 30
--concurrency 3
--case-timeout 1800
--embedding-backend hcvr-dual-lora
--embedding-device cuda
--embedding-batch-size 16
--text-max-chars 4000
--top-k 50000
```

## Metrics

| Metric | Value |
| --- | ---: |
| Completed / Failed | 30 / 0 |
| Elapsed seconds | 1642.106 |
| Total candidates | 349,262 |
| Mean candidates per completed case | 11,642.07 |
| Hit@10 | 0/30 = 0.0% |
| Hit@30 | 0/30 = 0.0% |
| Hit@50 | 2/30 = 6.7% |
| Hit@100 | 3/30 = 10.0% |
| Hit@200 | 7/30 = 23.3% |
| Hit@1000 | 12/30 = 40.0% |
| Hit@5000 | 24/30 = 80.0% |
| Hit@10000 | 26/30 = 86.7% |
| Hit@50000 | 30/30 = 100.0% |
| MRR | 0.004002 |

The queue summary only records the default budget set up to Hit@200. Hit@1000
and larger values were recomputed from `recall_results.jsonl.gz`.

## Files

- `summary.json`: queue-level summary emitted by the runner.
- `events.jsonl`: queue scheduling and per-case completion events.
- `selected_cases.jsonl`: selected case ledger for this run.
- `recall_results.jsonl.gz`: compressed raw per-case recall result rows.

File SHA256:

| File | SHA256 |
| --- | --- |
| `summary.json` | `70264674d06baa856808ca4094e98c1c204d566caa55e1c3efedf71ddaa7fad8` |
| `events.jsonl` | `31330359338152269fded50239e5d1724278a196cdd0b4634766a79c9f36b7f6` |
| `selected_cases.jsonl` | `2a1bf51f52e3f9879fe0bd35f0bd516959b5cb98be1fa8de53535155dfc5583d` |
| `recall_results.jsonl.gz` | `ee6032cc79660e40dc7d6ab369088ffa33a9a9151fac58344cdfb0c67360e9d8` |

To inspect raw rows:

```bash
gzip -dc recall_results.jsonl.gz | jq -c '.'
```
