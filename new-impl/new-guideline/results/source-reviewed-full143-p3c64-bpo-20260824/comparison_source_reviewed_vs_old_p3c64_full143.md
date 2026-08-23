# HCVR Recall Rank Comparison

- Left: `source-reviewed-baseline-plus-override-full143` (143 rows)
- Right: `old-p3c64-fixed143` (143 rows)
- Common identities: 143
- Same identity set: True
- Same identity order: True
- Mismatch allowed: False

## Metrics On Common Identities

| Metric | Left | Right | Delta |
| --- | ---: | ---: | ---: |
| Hit@160 | 84/143 | 83/143 | 1 |
| Hit@1000 | 85/143 | 116/143 | -31 |
| MRR | 0.087413 | 0.088528 | -0.001115 |

## Primary Budget Crossing: Top-160

- Both hit: 83
- Left-only hit: 1
- Right-only hit: 0
- Both miss: 59

### Left-Only Hits

- `xwiki__xwiki-rendering::CVE-2025-66474` left=86 right=248 type=`template_expression_injection`
