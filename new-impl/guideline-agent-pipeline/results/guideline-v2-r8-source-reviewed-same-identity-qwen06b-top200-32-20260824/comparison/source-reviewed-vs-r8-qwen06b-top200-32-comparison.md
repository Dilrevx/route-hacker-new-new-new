# HCVR Recall Rank Comparison

- Left: `source-reviewed-release-candidate` (32 rows)
- Right: `r8-release-ready-sidecar` (32 rows)
- Common identities: 32
- Same identity set: True
- Same identity order: True
- Mismatch allowed: False

## Metrics On Common Identities

| Metric | Left | Right | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 23/32 | 16/32 | 7 |
| Hit@50 | 24/32 | 17/32 | 7 |
| Hit@100 | 28/32 | 21/32 | 7 |
| Hit@150 | 28/32 | 23/32 | 5 |
| Hit@200 | 29/32 | 23/32 | 6 |
| MRR | 0.262389 | 0.210817 | 0.051571 |

## Primary Budget Crossing: Top-200

- Both hit: 23
- Left-only hit: 6
- Right-only hit: 0
- Both miss: 3

### Left-Only Hits

- `hubspot__jinjava::CVE-2020-12668` left=1 right=None type=`template_expression_injection`
- `hubspot__jinjava::CVE-2025-59340` left=3 right=None type=`template_expression_injection`
- `browserup__browserup-proxy::CVE-2020-26282` left=5 right=None type=`template_expression_injection`
- `hubspot__jinjava::CVE-2026-25526` left=5 right=None type=`template_expression_injection`
- `dhis2__dhis2-core::CVE-2022-41949` left=10 right=None type=`ssrf`
- `opensolon__solon::CVE-2025-1584` left=11 right=None type=`iris`
