# HCVR Recall Rank Comparison

- Left: `source-reviewed-release-candidate-common28` (28 rows)
- Right: `r8-release-ready-sidecar-common28` (28 rows)
- Common identities: 28
- Same identity set: True
- Same identity order: True
- Mismatch allowed: False

## Metrics On Common Identities

| Metric | Left | Right | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 20/28 | 14/28 | 6 |
| Hit@50 | 21/28 | 15/28 | 6 |
| Hit@100 | 24/28 | 18/28 | 6 |
| Hit@150 | 24/28 | 20/28 | 4 |
| Hit@200 | 25/28 | 20/28 | 5 |
| MRR | 0.256864 | 0.203393 | 0.053471 |

## Primary Budget Crossing: Top-200

- Both hit: 20
- Left-only hit: 5
- Right-only hit: 0
- Both miss: 3

### Left-Only Hits

- `hubspot__jinjava::CVE-2020-12668` left=1 right=None type=`template_expression_injection`
- `hubspot__jinjava::CVE-2025-59340` left=3 right=None type=`template_expression_injection`
- `browserup__browserup-proxy::CVE-2020-26282` left=5 right=None type=`template_expression_injection`
- `hubspot__jinjava::CVE-2026-25526` left=5 right=None type=`template_expression_injection`
- `dhis2__dhis2-core::CVE-2022-41949` left=10 right=None type=`ssrf`
