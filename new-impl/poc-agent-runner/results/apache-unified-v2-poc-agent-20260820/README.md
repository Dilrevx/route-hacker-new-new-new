# Apache Unified v2 PoC-Agent Verification Snapshot

This snapshot tracks selected PoC-agent verification results for the Apache
Codex Security progress export:

- Source snapshot:
  `new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/`
- Source commit:
  `dac7e7e Export Apache Codex Security progress snapshot`
- Queue size: 40 Apache project audits
- Candidate findings in source snapshot: 168

The rows here are triaged verification outputs, not a rerun of all 168
findings. Raw TraeX event streams, prompts, local source checkouts, and absolute
runtime paths are intentionally excluded.

## Current Results

| Rank | Finding ID | Repository | Candidate | Audited Revision | Verdict | Reportability |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `csf_fcd383a8ea47b07156e8d098` | `apache__activemq` | Fileserver MOVE arbitrary process-writable destination | `4ba1a1689f33d81bd2349a2bb8c66f0c95b04d1d` (`activemq-5.11.0`) | `CONFIRMED` for the pinned revision | Historical/revision-specific; not evidence that latest master is vulnerable. |
| 2 | `csf_0983b2b79357f77f78d5563b` | `apache__activemq` | HTTP XStream wire-format unsafe deserialization | `4ba1a1689f33d81bd2349a2bb8c66f0c95b04d1d` (`activemq-5.11.0`) | `NOT_VULNERABLE` as a new vendor report | Real historical condition, already covered by Apache CVE-2015-5254 / AMQ-6013 remediation. |

## Files

- `verification-summary.md` — concise batch verification summary.
- `cases.csv` — machine-readable current verification rows.
- `01-apache-activemq-e8d098/VERIFICATION_REPORT.md` — detailed fileserver
  verification report and evidence references.
- `01-apache-activemq-e8d098/evidence/` — sanitized source excerpts, local-only
  receipt, and SHA-256 manifest.
- `02-apache-activemq-d5563b/verification-report.md` — detailed HTTP XStream
  duplicate/historical rejection report.
- `02-apache-activemq-d5563b/evidence/` — source/history receipt, Apache
  advisory copy, and SHA-256 manifest.

## Operational Notes

- The first direct PoC-agent attempt for candidate 1 failed before producing a
  verdict because the model stream ended with `sensitive_content`. The retained
  result is from a second, local-only verification prompt.
- Both retained ActiveMQ reviews use the exact pinned revision from the Apache
  queue, which is `activemq-5.11.0`; this is not a latest-master revision.
- No live external targets were contacted. The fileserver confirmation uses a
  non-network local receipt. The XStream review did not run a live Java harness
  because the local host did not have a usable Java runtime or Maven.
