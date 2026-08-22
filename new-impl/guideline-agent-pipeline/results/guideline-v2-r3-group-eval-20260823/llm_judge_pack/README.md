# LLM Judge Pack

This pack is for semantic guideline-group review. It is intentionally separate from embedding recall evaluation and from the structural HCVR/CWE sanity checker.

Judgment target: whether the guideline captures a coherent reusable vulnerability mechanism across the listed cases, and whether the text is actionable as an audit query.

Run from this directory:

```bash
TRAE_JUDGE_TIMEOUT=30m ./run_traex_judge.sh judge_outputs
```

For a single group:

```bash
timeout 30m traecli exec -o judge_outputs/gl_mech_0001.json < prompts/gl_mech_0001.md
```

The expected response is JSON with `decision`, four 0..1 scores, and short revision or split suggestions.
LLM judge output is advisory evidence for guideline iteration; it is not used to build online retrieval queries.
