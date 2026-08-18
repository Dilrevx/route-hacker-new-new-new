# Oracle-Anchor Audit 142 Result

## Scope

This result summarizes the 142-case TraeX audit run over dataset-provided anchors. The runner selected `recall_anchors[0]` from `new_unified_cases.v1.jsonl` for each case and asked `DeepSeek-V4-Flash` to audit that anchor. This is an oracle/preselected-anchor audit baseline, not an online guideline-recall evaluation.

## Overall

| Metric | Value |
| --- | ---: |
| Total cases | 142 |
| Completed with parseable binary decision | 109 |
| Risk decisions | 64 |
| No-risk decisions | 45 |
| Timeout | 30 |
| Invalid footer | 3 |
| Risk / all cases | 45.1% |
| Risk / decided cases | 58.7% |
| Decidable rate | 76.8% |

## Token And Time Accounting

| Metric | Value |
| --- | ---: |
| Input tokens | 206,804,148 |
| Cached input tokens | 191,068,672 |
| Output tokens | 10,225,334 |
| Reasoning output tokens | 9,079,998 |
| Estimated billable input tokens | 15,735,476 |
| Estimated billable total tokens | 25,960,810 |
| Total tokens including cached | 217,029,482 |
| Avg estimated billable tokens / case | 182,823 |
| Artifact mtime span, old + new | 4.62 h |

## By HCVR Type

| HCVR type | n | risk | no-risk | timeout | invalid | risk / decided |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `authentication_session_token_validation` | 9 | 5 | 0 | 3 | 1 | 100.0% |
| `authorization_bypass` | 15 | 13 | 1 | 1 | 0 | 92.9% |
| `business_state_precondition` | 14 | 4 | 8 | 2 | 0 | 33.3% |
| `concurrent_object_lifecycle` | 12 | 1 | 8 | 3 | 0 | 11.1% |
| `cve_2026_50279` | 1 | 0 | 0 | 1 | 0 | n/a |
| `file_permission_temp_resource` | 9 | 7 | 2 | 0 | 0 | 77.8% |
| `ghsa_7rx3_5wx3_5v76` | 1 | 1 | 0 | 0 | 0 | 100.0% |
| `iris` | 47 | 20 | 12 | 14 | 1 | 62.5% |
| `m9_expansion` | 3 | 2 | 0 | 1 | 0 | 100.0% |
| `m9_wave2` | 5 | 2 | 2 | 1 | 0 | 50.0% |
| `m9_wave4` | 6 | 2 | 4 | 0 | 0 | 33.3% |
| `open_redirect` | 4 | 1 | 2 | 0 | 1 | 33.3% |
| `ssrf` | 4 | 3 | 1 | 0 | 0 | 75.0% |
| `template_expression_injection` | 2 | 1 | 0 | 1 | 0 | 100.0% |
| `toctou_check_use_race` | 10 | 2 | 5 | 3 | 0 | 28.6% |

## By Paper Eval Decision

| Group | n | risk | no-risk | timeout | invalid | risk / decided |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `blocked_for_fix_revision_eval` | 2 | 2 | 0 | 0 | 0 | 100.0% |
| `paper_ready_aux_fix_only` | 46 | 23 | 11 | 11 | 1 | 67.6% |
| `paper_ready_direct_pair` | 94 | 39 | 34 | 19 | 2 | 53.4% |

## Interpretation

- This run measures audit behavior after an anchor is already supplied by the dataset. It does not measure whether a guideline can retrieve that anchor from a repository.
- `risk` on these positive CVE cases is an oracle-anchor hit signal. `no-risk` is a candidate false negative or an anchor/context mismatch requiring review. `timeout` and `invalid_report_footer` are undecided.
- The strongest families in this run are authorization/session/file-permission/SSRF-style patterns. TOCTOU, concurrent lifecycle, and business-state precondition cases are weaker and need prompt or context improvements.

## Files

- `aggregate_summary.json`: machine-readable aggregate metrics.
- `per_case_audit_index.jsonl` / `.csv`: one row per audited case.
- `risk_cases.jsonl`, `no_risk_cases.jsonl`, `timeout_cases.jsonl`, `invalid_footer_cases.jsonl`, `undecided_cases.jsonl`: convenience splits.

