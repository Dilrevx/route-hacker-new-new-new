# Apache Unified v2 PoC-Agent Verification Summary

Updated: 2026-08-20

Source snapshot:
`new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/`

This verification pass started from the 168 Codex Security finding candidates
in the Apache unified v2 progress snapshot. Candidates were triaged before
PoC-agent execution; the first two high-signal ActiveMQ findings have completed.

## Summary

| Metric | Value |
| --- | ---: |
| Snapshot queue size | 40 |
| Terminal scan records in snapshot | 22 |
| Candidate findings in snapshot | 168 |
| PoC-agent candidates started | 2 |
| Completed PoC-agent reviews | 2 |
| Confirmed on pinned revision | 1 |
| Rejected as new vendor report | 1 |

## Completed Reviews

### 1. ActiveMQ fileserver arbitrary write

- Finding ID: `csf_fcd383a8ea47b07156e8d098`
- Rule ID: `path-traversal.fileserver-move-arbitrary-write`
- Audited revision:
  `4ba1a1689f33d81bd2349a2bb8c66f0c95b04d1d` (`activemq-5.11.0`)
- Verdict: `CONFIRMED` for the pinned revision.
- Boundary: source-backed and local-receipt-backed confirmation of an arbitrary
  process-writable destination through the fileserver `MOVE` path. It does not
  claim that latest master remains vulnerable.
- Report: `01-apache-activemq-e8d098/VERIFICATION_REPORT.md`
- Evidence: `01-apache-activemq-e8d098/evidence/`

### 2. ActiveMQ HTTP XStream wire format

- Finding ID: `csf_0983b2b79357f77f78d5563b`
- Rule ID: `unsafe-deserialization.http-xstream-wireformat`
- Audited revision:
  `4ba1a1689f33d81bd2349a2bb8c66f0c95b04d1d` (`activemq-5.11.0`)
- Verdict: `NOT_VULNERABLE` as a new vendor-reportable finding.
- Boundary: the source path is real for the historical 5.11.0 revision, but it
  is already covered by Apache CVE-2015-5254 / AMQ-6013 remediation history.
- Report: `02-apache-activemq-d5563b/verification-report.md`
- Evidence: `02-apache-activemq-d5563b/evidence/`

## Notes

- Original Codex Security findings remain candidates. This directory stores only
  verification outputs for selected findings.
- Raw agent event streams, local source checkouts, prompts, and local runtime
  logs are excluded from the repository snapshot.
- For vendor disclosure, these results require an additional current-release or
  latest-master deduplication pass before any new report is drafted.
