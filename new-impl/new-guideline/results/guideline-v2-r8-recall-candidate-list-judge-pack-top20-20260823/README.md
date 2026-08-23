# Recall Candidate List Judge Pack

This pack asks TraeX/LLM-as-judge to score shuffled Top-N recall candidates for each case.
It is advisory semantic QA only: it does not update guidelines, does not score embedding recall, and does not gate Top-K claims.

## Inputs

- Identities: 6
- Prompt shards: 12
- Candidate max rank: 20
- Candidates per prompt: 10
- Skipped unreadable snippets: 0

Each prompt omits original rank, score, known-anchor labels, CVE IDs, and benchmark metadata.
`judge_inputs.jsonl` keeps hidden metadata only for offline analysis after judge completion.

## Run

```bash
TRAE_JUDGE_CLI=traex TRAE_JUDGE_MODEL=DeepSeek-V4-Pro TRAE_JUDGE_EXTRA_ARGS='--disallowed-tool exec' TRAE_JUDGE_CONCURRENCY=2 TRAE_JUDGE_TIMEOUT_SECONDS=1800 ./run_traex_judge.sh judge_outputs
```

The runner defaults to `traex`. Defaults to `DeepSeek-V4-Pro`. Override both with environment variables when the local provider changes.

## Summarize

```bash
python3 ../../scripts/summarize_recall_candidate_list_judge_outputs.py \
  --judge-inputs judge_inputs.jsonl \
  --judge-output-dir judge_outputs \
  --output-dir judge_summary
```

Use this only to decide whether a semantic reranker/query A/B is worth running. Do not feed choices back into retrieval labels or guideline generation.
