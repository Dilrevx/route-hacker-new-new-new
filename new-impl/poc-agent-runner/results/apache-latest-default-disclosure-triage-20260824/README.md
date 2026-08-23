# Apache latest/default disclosure triage ledger

Updated: 2026-08-24

This ledger records Apache latest/default Codex Security candidates that have
already passed through the manual discussion and PoC-agent triage workflow. It
is an operational index, not a public vulnerability claim list.

Source snapshots:

- `new-impl/codex_security_batch/results/apache-unified-v2-latest-default-gpt55-high-progress-20260822/`
- `new-impl/codex_security_batch/results/apache-unified-v2-latest-default-gpt55-high-final-20260823/`

Disclosure hygiene:

- Runtime PoC bundles and email draft bodies are not committed here.
- Rows marked reportable still require the usual private disclosure handling and
  maintainer security-model review.
- Rows marked not reported are preserved so later batches do not spend budget on
  the same candidate without new evidence.

## Processed candidates

| Project | Finding ID | PoC status | Triage outcome | Notes |
| --- | --- | --- | --- | --- |
| Apache ActiveMQ | `csf_292e1f7d633ee069b3d50b68` | Confirmed | Reportable candidate | HTTP discovery registry accepted unauthenticated endpoint publication/removal in the tested latest/default revision; handled in the private disclosure workflow. |
| Apache ActiveMQ Artemis | `csf_3d425881daa2c96bd9968a9d` | Confirmed | Reportable candidate | OpenWire durable subscription removal bypassed the control-path queue delete authorization check; handled in the private disclosure workflow. |
| Apache Camel | `csf_8a5accddbd0026c2a35dfc97` | Confirmed by dynamic artifact | Reportable candidate | Malicious remote FTP listing names drove read/delete paths outside the configured polling directory; handled in the private disclosure workflow. |
| Apache Cassandra | `csf_9244df69ff5fc732087916e4` | Confirmed | Reportable candidate | `ADD IDENTITY` authorization relied on broad role-creation permission instead of target-role control; handled in the private disclosure workflow. |
| Apache Axis Axis1 Java | n/a | Not run | Skipped by revision gate | Latest/default branch revision predates the 2026 freshness rule for new-project false-positive audit. |
| Apache Commons Text | `csf_df654b95dcad7cf6378c737a` | Confirmed | Reportable candidate | Fenced direct lookups were blocked, while the documented fenced `StringSubstitutor` composition path reached unfenced file/properties/XML lookups. |
| Apache Dubbo | `csf_710cf8f3d98e44e174496098` | Confirmed | Reportable candidate | Empty descriptor dispatch reached implementation-only zero-argument methods outside the exported service interface boundary. |
| Apache RocketMQ | `csf_0270c2613bdce87f82389e2c` | Confirmed | Conservative disclosure candidate | NameServer admin RPC mutation was confirmed on latest/default; reportability is weaker until ACL-enabled controls are checked against the project security model. |
| Apache Tika | `csf_2ae2dcef1ce52fe549452257` | Confirmed | Not reported in this pass | The tested Pipes HTTP fetcher path overlaps documented trusted-caller and opt-in `allowPipes` assumptions, so it was deprioritized as a vulnerability report. |

## Current batch accounting

| Bucket | Count |
| --- | ---: |
| Processed latest/default candidates in this ledger | 9 |
| Confirmed reportable candidates | 6 |
| Conservative disclosure candidates | 1 |
| Confirmed but not reported | 1 |
| Revision-gate skips | 1 |

Use `cases.csv` in this directory for a script-friendly view of the same
state.
