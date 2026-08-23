# P3C64 Fixed-143 Paper-Eval Result

This is the valid same-identity 143-case result for the recovered HCVR/P3C64
retriever.

## Boundary

- Dataset: Unified V2 paper-eval 143-case identity allowlist.
- Identity file SHA256:
  `e00a8622f2321ea86248de87a2cbbf89b388798e6e6a0d9df6bfbaf69191b805`.
- P3C64 completed: 143/143.
- Failed/missing: 0.
- Candidate anchors: 1,094,013.
- Mean candidates / case: 7,650.44.
- MRR: 0.088528.
- Full remote run root:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-fixed143-20260820T113743`.

## Hit@K

| K | Hit Count | Rate |
| ---: | ---: | ---: |
| 30 | 45 | 0.3147 |
| 50 | 56 | 0.3916 |
| 100 | 73 | 0.5105 |
| 200 | 84 | 0.5874 |
| 300 | 91 | 0.6364 |
| 500 | 103 | 0.7203 |

## Same-Identity A/B Against Qwen3-Embedding-4B

| Budget | Qwen3-Embedding-4B | P3C64 query-residual | Delta |
| --- | ---: | ---: | ---: |
| Top-30 | 30/143 = 0.2098 | 45/143 = 0.3147 | +15 cases / +10.5 pp |
| Top-50 | 37/143 = 0.2587 | 56/143 = 0.3916 | +19 cases / +13.3 pp |
| Top-100 | 55/143 = 0.3846 | 73/143 = 0.5105 | +18 cases / +12.6 pp |
| Top-150 | 65/143 = 0.4545 | 83/143 = 0.5804 | +18 cases / +12.6 pp |
| Top-200 | 74/143 = 0.5175 | 84/143 = 0.5874 | +10 cases / +7.0 pp |
| Top-300 | 82/143 = 0.5734 | 91/143 = 0.6364 | +9 cases / +6.3 pp |
| Top-500 | 94/143 = 0.6573 | 103/143 = 0.7203 | +9 cases / +6.3 pp |

Use Top-100 or Top-150 for the paper claim that P3C64 improves recall by more
than 10 percentage points. Use Top-200 as `+10 recovered cases`.

## Local Artifacts

- `summary.json`: P3C64 metrics and provenance.
- `qwen4b_comparison.md` / `qwen4b_comparison.json`: same-identity A/B.
- `p3c64_case_rank_table.jsonl`: one compact row per case for P3C64.
- `qwen4b_case_rank_table.jsonl`: one compact row per case for Qwen4B.
- `selected_cases.jsonl`: Top-1 recalled anchor per case for downstream audit.
- `paper_eval_143_identities.jsonl`: frozen identity allowlist.

The full per-anchor ranking files are intentionally not committed because each
full `recall_results.jsonl` is roughly 386MB. Authoritative remote paths:

```text
P3C64: /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-fixed143-20260820T113743/final_merged/recall_results.jsonl
Qwen4B: /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-fixed143-20260820T113743/qwen4b_full_recall_merged/recall_results.jsonl
```

## Interpretation

This run validates the P3C64 query-only residual adapter under the current
guideline text. Guideline-v2 support has been added to the pipeline through
`--guideline-file`, but a new metric claim for guideline quality requires a
fresh rerun on the same identity file.
