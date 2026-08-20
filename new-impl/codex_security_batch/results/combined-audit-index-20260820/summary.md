# Combined Audit and PoC Verification Index

Generated: 2026-08-20

This directory is a portable index over recent committed scanner snapshots and local PoC-agent verification outcomes. It intentionally records summaries and machine-readable tables only; raw agent event streams, prompts, local source checkouts, credentials, and absolute local artifact paths are excluded.

## Count Semantics

The 143-case rows are cumulative snapshots of the same queue. Do not add `native-blind-batch-20260817`, `traex-continuation-143-pre-run-20260819`, and `143-case-through-case111-20260820` together as independent alerts. The representative 143-case count is the latest committed `143-case-through-case111-20260820` snapshot.

Current representative candidate universe covered by this index:

| Scope | Findings | Critical | High | Medium | Low | Critical+High |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Latest 143-case snapshot + Apache unified-v2 snapshot + Axis latest-HEAD smoke | 835 | 31 | 368 | 384 | 52 | 399 |

All exported snapshot rows, including cumulative intermediate snapshots for historical comparison, contain 1868 finding rows. That number is intentionally non-deduplicated.

## Batch Snapshots

| Batch | Lineage | Representative | Processed / Queue | Findings | Critical | High | Critical+High | Notes |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| `native-blind-batch-20260817` | 143-case-cumulative | no | 63 / 143 | 396 | 13 | 161 | 174 | Earlier cumulative snapshot for the 143-case queue; do not add to later 143-case snapshots. |
| `traex-continuation-143-pre-run-20260819` | 143-case-cumulative | no | 103 / 143 | 637 | 24 | 265 | 289 | Intermediate cumulative snapshot for the same 143-case queue. |
| `143-case-through-case111-20260820` | 143-case-cumulative | yes | 111 / 143 | 659 | 24 | 283 | 307 | Latest committed representative snapshot for the 143-case queue. |
| `apache-unified-v2-gpt55-high-progress-20260820` | apache-unified-v2-project-audit | yes | 22 / 40 | 168 | 7 | 82 | 89 | 40-project Apache project-level blind audit snapshot. |
| `axis-axis1-java-latest-head-smoke-20260819` | apache-latest-head-smoke | yes | 1 / 1 | 8 | 0 | 3 | 3 | Local DeepAudit smoke export for apache/axis-axis1-java at 2c0d660; summarized here without raw local paths. |

Detailed tables:

- `batches.csv` lists each batch snapshot, status counts, severity counts, and source path.
- `critical_high_findings_by_snapshot.csv` lists every Critical/High finding from each exported snapshot, including cumulative intermediate snapshots.
- `representative_critical_high_findings.csv` lists Critical/High findings only from representative snapshots: latest 143-case, Apache unified-v2, and Axis latest-HEAD smoke.

## PoC-Agent Verification Coverage

Completed PoC-agent verdict rows listed here: 16. Initial PoC-agent verdict counts are:

| Verdict | Count |
| --- | ---: |
| `CONFIRMED` | 13 |
| `NOT_VULNERABLE_AS_NEW_VENDOR_REPORT` | 1 |
| `REJECTED` | 2 |

Final/discussion disposition counts are:

| Disposition | Count |
| --- | ---: |
| `confirmed_for_dataset_runtime` | 8 |
| `disputed_or_likely_not_vendor_reportable` | 1 |
| `duplicate_historical_CVE-2015-5254_AMQ-6013` | 1 |
| `historical_revision_specific_not_latest_master` | 1 |
| `rejected_by_poc_agent` | 2 |
| `review_rejected_wrong_effect` | 3 |

Important interpretation notes:

- `confirmed_for_dataset_runtime` means the PoC-agent demonstrated the reported effect on the prepared dataset/runtime target. It is not automatically a latest-HEAD or new vendor-report claim.
- `review_rejected_wrong_effect` means the PoC-agent initially claimed a runnable confirmation, but a follow-up reviewer found the demonstrated effect did not match the dataset CVE/root-cause being validated.
- `historical_revision_specific_not_latest_master` means the candidate was confirmed on a pinned historical revision only.
- `duplicate_historical_CVE-2015-5254_AMQ-6013` means the unsafe condition was real historically but is not a new vendor report.
- `disputed_or_likely_not_vendor_reportable` currently applies to the Axis SOAP/DIME attachment upload/resource-exhaustion case: a standard Axis service that accesses attachments can materialize attacker-controlled DIME attachment bytes to temp files, but the default Version service did not materialize attachments, so vendor acceptance is doubtful without a stronger default-service exploitability argument.

Upload/file-transfer related rows that are explicitly represented:

- ActiveMQ fileserver PUT/MOVE arbitrary file write: PoC-agent `CONFIRMED` on pinned ActiveMQ 5.11.0, final disposition `historical_revision_specific_not_latest_master`.
- Axis DIME/SOAP attachment upload/materialization: PoC-agent `CONFIRMED`, later HTTP validation narrowed scope to attachment-consuming services; final disposition `disputed_or_likely_not_vendor_reportable`.
- OpenMeetings FileWebService negative-parent file metadata case: PoC-agent run attempted but exceeded token limit; no completed PoC-agent verdict in this index.

Detailed tables:

- `poc_agent_outcomes.csv` lists every completed PoC-agent verdict row currently recovered and the final discussion disposition.
- `poc_agent_run_attempts.csv` lists failed, interrupted, token-limited, and prepared-but-not-run attempts.
- `disposition_counts.csv` gives compact counts for both initial verdicts and final dispositions.

## Current Bottom Line

The scanner snapshots provide candidate queues, not verified vulnerabilities. For the currently indexed representative scans, the candidate volume is 835 findings with 31 Critical and 368 High rows. The recovered completed PoC-agent validations contain 16 verdict rows: 13 initial `CONFIRMED`-style rows and 3 initial rejected/not-new rows. After follow-up review and discussion, 8 rows remain cleanly confirmed for their dataset/runtime target, while the rest are rejected, duplicate/historical, latest-master-limited, or vendor-reportability-disputed.
