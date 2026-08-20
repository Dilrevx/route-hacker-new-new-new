# P3C64 + Qwen4B Anchor-Level RRF Fusion, Frozen 143

This result fuses two same-identity full-143 recall runs:

- Left: `p3c64-query-residual`
- Right: `qwen3-embedding-4b`
- Fusion: reciprocal rank fusion over anchor keys
- Parameters: `left_weight=1.5`, `right_weight=1.0`, `rrf_k=60`, `per_source_cap=1000`
- Identity file SHA256: `e00a8622f2321ea86248de87a2cbbf89b388798e6e6a0d9df6bfbaf69191b805`

Remote artifact:

```text
/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-fixed143-20260820T113743/fused_p3c64_qwen4b_rrf_w1p5_cap1000_v2/
```

Key outputs:

```text
recall_results.jsonl
selected_cases.jsonl
summary.json
compare_to_p3c64.json
compare_to_p3c64.md
compare_to_qwen4b.json
compare_to_qwen4b.md
```

## Metrics

| Run | Hit@30 | Hit@50 | Hit@100 | Hit@200 | Hit@300 | Hit@500 | MRR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3-Embedding-4B | 30 | 37 | 55 | 74 | 82 | 94 | 0.050733 |
| P3C64 query residual | 45 | 56 | 73 | 84 | 91 | 103 | 0.088528 |
| P3C64 + Qwen4B RRF | 48 | 55 | 70 | 90 | 95 | 105 | 0.092715 |

Compared with P3C64 alone, RRF improves wider-budget recall:

| Budget | Delta |
| ---: | ---: |
| Hit@30 | +3 |
| Hit@50 | -1 |
| Hit@100 | -3 |
| Hit@200 | +6 |
| Hit@300 | +4 |
| Hit@500 | +2 |
| MRR | +0.004187 |

Compared with Qwen3-Embedding-4B alone, RRF improves all reported budgets:

| Budget | Delta |
| ---: | ---: |
| Hit@30 | +18 |
| Hit@50 | +18 |
| Hit@100 | +15 |
| Hit@200 | +16 |
| Hit@300 | +13 |
| Hit@500 | +11 |
| MRR | +0.041982 |

## Interpretation

The fusion is a practical improvement for Top-200/300/500 recall and for MRR,
but it is not a strict replacement for P3C64 at every budget because Hit@50 and
Hit@100 are slightly lower than P3C64 alone. Use it when the downstream audit
budget is around Top-200 or larger.
