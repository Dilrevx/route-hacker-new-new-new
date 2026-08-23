# Ledger Boundary Judge Pack

This pack asks TraeX/LLM-as-judge to review source-reviewed guideline ledger rows.
It is advisory semantic QA only: it does not update guidelines, does not score embedding recall, and does not gate Top-K claims.

## Inputs

- Ledger: `new-impl/guideline-agent-pipeline/guidelines/guideline_review_ledger.r8.gl_mech_0022.jsonl`
- Rows: 2
- Rubric: `judge_rubric.v1.md`

## Run

```bash
TRAE_JUDGE_CLI=traex TRAE_JUDGE_MODEL=DeepSeek-V4-Pro TRAE_JUDGE_EXTRA_ARGS='--disallowed-tool exec' TRAE_JUDGE_CONCURRENCY=4 TRAE_JUDGE_TIMEOUT_SECONDS=1800 ./run_traex_judge.sh judge_outputs
```

The runner defaults to `traex`. Defaults to `DeepSeek-V4-Pro`. Override both with environment variables when the local provider changes.
Use `TRAE_JUDGE_EXTRA_ARGS='--disallowed-tool exec'` when the judge should return only its final JSON and avoid tool-call side effects.

## Summarize

```bash
python3 ../../scripts/summarize_guideline_judge_outputs.py \
  --judge-inputs judge_inputs.jsonl \
  --judge-output-dir judge_outputs \
  --output-dir judge_summary
```

Use the summary as a review queue. Do not feed judge decisions back into recall labels without source review and same-identity recall reruns.
