# HCVR Recall Rank Comparison

- Left: `r7-evidence-gated-full143-p3c64` (143 rows)
- Right: `old-p3c64-full143-baseline` (143 rows)
- Common identities: 143
- Same identity set: True
- Same identity order: True
- Mismatch allowed: False

## Metrics On Common Identities

| Metric | Left | Right | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 47/143 | 45/143 | 2 |
| Hit@50 | 58/143 | 56/143 | 2 |
| Hit@100 | 76/143 | 73/143 | 3 |
| Hit@150 | 85/143 | 83/143 | 2 |
| Hit@200 | 87/143 | 84/143 | 3 |
| Hit@300 | 96/143 | 91/143 | 5 |
| Hit@500 | 106/143 | 103/143 | 3 |
| MRR | 0.097064 | 0.088528 | 0.008536 |

## Primary Budget Crossing: Top-100

- Both hit: 72
- Left-only hit: 4
- Right-only hit: 1
- Both miss: 66

### Left-Only Hits

- `keycloak__keycloak::CVE-2022-4361` left=25 right=2524 type=`iris`
- `xwiki__xwiki-commons::CVE-2024-31996` left=40 right=150 type=`template_expression_injection`
- `useplunk__plunk::CVE-2026-32096` left=43 right=106 type=`ssrf`
- `xwiki__xwiki-rendering::CVE-2025-66474` left=71 right=248 type=`template_expression_injection`

### Right-Only Hits

- `code16__sharp::CVE-2026-53634` right=74 left=104 type=`m9_expansion`
