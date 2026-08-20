# Codex Security vs Unified v2 Ground-Truth Anchor Alignment

## Metric

A strict hit requires the finding's exported primary path to equal a GT recall-anchor path and its primary start line to fall inside that anchor's labeled line span. This is evaluated after blind scanning and is a localization proxy, not semantic CVE confirmation.

| Metric | Value |
| --- | ---: |
| GT-joined cases | 143 |
| Strict anchor-hit cases | 18 |
| Strict anchor-hit rate | 12.59% |
| Same-anchor-file only cases | 22 |
| Findings elsewhere cases | 93 |
| No-findings cases | 10 |
| Strict-overlap findings | 21 |
| Same-file non-overlap findings | 40 |
| Different-file findings | 676 |

## Outputs

- `case_gt_alignment.csv`: one GT alignment row per audited case.
- `finding_gt_alignment.csv`: one relation label per emitted finding.
