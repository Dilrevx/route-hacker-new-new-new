# Recall Candidate Pair Judge Pack

This pack asks TraeX/LLM-as-judge to compare anonymous recall candidates for semantically clean ranked misses.
It is advisory semantic QA only: it does not update guidelines, does not score embedding recall, and does not gate Top-K claims.

## Inputs

- Pair prompts: 6
- Each prompt compares the current Top-1 candidate with the best exported known-anchor-overlap candidate.
- The prompt omits rank, score, known-anchor labels, CVE IDs, and benchmark metadata.
- By default, pairs whose source snippets cannot be read from the snapshot path are skipped.
- `judge_inputs.jsonl` keeps hidden labels for offline analysis after the judge run.

## Run

```bash
TRAE_JUDGE_CLI=traex TRAE_JUDGE_MODEL=DeepSeek-V4-Pro TRAE_JUDGE_EXTRA_ARGS='--disallowed-tool exec' TRAE_JUDGE_CONCURRENCY=2 TRAE_JUDGE_TIMEOUT_SECONDS=1800 ./run_traex_judge.sh judge_outputs
```

The runner defaults to `traex`. Defaults to `DeepSeek-V4-Pro`. Override both with environment variables when the local provider changes.

## Summarize

```bash
python3 ../../scripts/summarize_recall_candidate_pair_judge_outputs.py \
  --judge-inputs judge_inputs.jsonl \
  --judge-output-dir judge_outputs \
  --output-dir judge_summary
```

Use this only to decide whether a semantic reranker is worth a same-identity A/B. Do not feed choices back into retrieval labels or guideline generation.
