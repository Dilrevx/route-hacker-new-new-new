# route-hacker-new

Clean new implementation workspace for Route-Hacker experiments.

Current main module: `new-impl/guideline-agent-pipeline/` contains the
guideline-conditioned recall and audit pipeline.

## Execution Note

Use `bobo5090` for remote source materialization, embedding services, and
recall jobs. Do not use `bobo5090` as the LLM audit provider host. Its AI
provider paths are currently considered unavailable for this project: Codex /
TraeX / direct provider calls from that host timed out for both
`DeepSeek-V4-Pro` and `DeepSeek-V4-Flash`.

Run the audit stage from the local development machine instead, using the local
Codex or TraeX login and model access. Known intended audit models include
`DeepSeek-V4-Pro`, `GPT-5.5`, or another locally available model configured in
the local Codex/TraeX provider stack. Keep `bobo5090` as the recall/embedding
host, then mount or copy the recall artifacts for local audit execution.

## Experiment Result Index

This section records where current Unified V2 experiment artifacts live. Large
outputs are intentionally stored outside the Git checkout; this index records
the paths and whether a result is usable for paper tables.

### Backend-B Model Ablation

Paper-comparable backend-B rows must use the same Unified V2 paper-eval
143-case set, the same recall receipt, and the same audit budget:

```text
Top-K = 200 recalled anchors per case
m = 10 anchors per grouped audit prompt
groups per case = 20
```

Use `new-impl/guideline-agent-pipeline/scripts/run_hcvr_backend_b_model_queue.py`
for model rows. The only intended per-row change is `--model`.

Current local staging paths:

- Correct queue entrypoint:
  `new-impl/guideline-agent-pipeline/scripts/run_hcvr_backend_b_model_queue.py`
- Correct DeepSeek staging root:
  `/Users/bytedance/tmp/hcvr-backend-b-deepseek-flash-top200-m10-*`
  once launched with `--top-k 200 --m 10`.
- Deprecated local root:
  `/Users/bytedance/tmp/hcvr-backend-b-full143-20260820`
  was an operator-error run with `Top-K=10, m=10`. It must not be used in the
  backend-B model ablation table. It is useful only as a failure note explaining
  why Top-K and `m` must be recorded separately.

### Embedding Model Size Ablation

Embedding-size recall experiments are separate from backend-B. Their results
live under the local/remote run roots named
`hcvr-embedding-qwen-size-runs` and should be reported as recall distribution
statistics, not bounded-audit backend metrics.
