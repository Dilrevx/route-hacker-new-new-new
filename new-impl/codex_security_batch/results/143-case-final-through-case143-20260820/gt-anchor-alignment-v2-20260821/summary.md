# Codex Security vs Unified v2 Ground-Truth Anchor Alignment

## Post-hoc localization tiers

The blind scan never receives GT. The broader reported-location overlap proxy considers every finding location and code-evidence span explicitly emitted by Codex Security; emitted locations are not assumed exhaustive. Primary-only overlap is retained as a conservative lower bound. Neither tier alone is semantic CVE confirmation.

| Metric | Value |
| --- | ---: |
| GT-joined cases | 143 |
| Primary-only lower-bound hit cases | 18 |
| Any reported-location anchor-overlap cases (proxy) | 45 |
| Any reported-location anchor-overlap rate (proxy) | 31.47% |
| Same-file within 50 lines, including hits (diagnostic) | 53 |
| Same-file within 50 lines rate (diagnostic) | 37.06% |
| Same-anchor-file cases, including nearby | 62 |
| Findings elsewhere cases | 71 |
| No-findings cases | 10 |
| Primary-only overlap findings | 21 |
| Any reported-location overlap findings | 67 |

## Outputs

- `case_gt_alignment.csv`: tier counts and strongest relation per case.
- `finding_gt_alignment.csv`: tier labels, closest GT-anchor distance, and matched locations per finding.
