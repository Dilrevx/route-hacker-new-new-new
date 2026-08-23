# P3C64 Half Fixed Case Subset

This directory defines the fixed 71-case subset for Backend-B model ablation probes.
The split preserves the P3C64 Top160 recalled/not-recalled ratio from the frozen Unified V2 143-case paper-eval set.

## Selection

- Seed: `p3c64-half-fixed-case-top160-v1`
- Primary budget: Top160
- Full set: 143 cases
- Full strata: 83 Top160-hit, 60 Top160-miss
- Half subset: 71 cases (41 Top160-hit, 30 Top160-miss)

## Input Hashes

| Input | SHA256 |
| --- | --- |
| `new-impl/guideline-agent-pipeline/results/p3c64-fixed143-paper-eval-20260820/p3c64_case_rank_table.jsonl` | `c4f5dcbe8f6898236d3953d04a5517d890d61b9f00aaabb6355518762f9a8704` |
| `new-impl/guideline-agent-pipeline/results/p3c64-fixed143-paper-eval-20260820/paper_eval_143_identities.jsonl` | `e00a8622f2321ea86248de87a2cbbf89b388798e6e6a0d9df6bfbaf69191b805` |

## Artifacts

- `selected_identity_allowlist.jsonl`: identity allowlist for the 71-case audit run.
- `selected_case_rank_table.jsonl`: selected rank rows with original index, sample key, and Top160 stratum.
- `manifest.json`: machine-readable provenance for the split.

## Reproduce

```bash
python3 new-impl/guideline-agent-pipeline/scripts/make_p3c64_half_fixed_case_subset.py \
  --rank-table new-impl/guideline-agent-pipeline/results/p3c64-fixed143-paper-eval-20260820/p3c64_case_rank_table.jsonl \
  --identity-file new-impl/guideline-agent-pipeline/results/p3c64-fixed143-paper-eval-20260820/paper_eval_143_identities.jsonl \
  --output-dir new-impl/guideline-agent-pipeline/results/p3c64-half-fixed-case-top160-v1
```
