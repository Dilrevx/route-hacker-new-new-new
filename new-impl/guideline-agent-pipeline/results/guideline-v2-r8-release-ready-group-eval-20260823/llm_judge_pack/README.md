# LLM Judge Pack

This pack is for semantic guideline-group review. It is intentionally separate from embedding recall evaluation and from the structural HCVR/CWE sanity checker.
The prompt rubric is stored in `judge_rubric.v1.md` so the judgment criteria can be reviewed and versioned independently from code.
The default recommended `balanced` filter samples evidence-limited, label-mixed, clean-control, small, and source-only groups in round-robin order, so review does not optimize only for historical bad cases or label-purity flags.

Judgment target: whether the guideline captures a coherent reusable vulnerability mechanism across the listed cases, and whether the text is actionable as an audit query.

Run from this directory:

```bash
TRAE_JUDGE_TIMEOUT_SECONDS=1800 TRAE_JUDGE_CONCURRENCY=4 ./run_traex_judge.sh judge_outputs
```

Summarize completed judge outputs:

```bash
python3 ../../../scripts/summarize_guideline_judge_outputs.py \
  --judge-inputs judge_inputs.jsonl \
  --judge-output-dir judge_outputs \
  --output-dir judge_summary
```

For a single group:

```bash
timeout 30m traecli exec -o judge_outputs/gl_mech_0001.json < prompts/gl_mech_0001.md
```

The expected response is JSON with `decision`, four 0..1 scores, and short revision or split suggestions.
LLM judge output is advisory evidence for guideline iteration; it is not used to build online retrieval queries.
