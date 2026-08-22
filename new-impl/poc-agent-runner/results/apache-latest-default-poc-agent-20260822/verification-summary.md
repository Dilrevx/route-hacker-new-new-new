# Apache Latest-Default PoC-Agent Verification Summary

Updated: 2026-08-22

Source snapshot:
`new-impl/codex_security_batch/results/apache-unified-v2-latest-default-gpt55-high-progress-20260822/`

This verification pass reviewed the first five Apache latest/default Codex
Security candidates from the 2026-08-22 progress export. The run applied the
new-project false-positive audit gate before PoC execution: the target
repository's frozen latest/default branch commit must be dated in 2026.

## Summary

| Metric | Value |
| --- | ---: |
| Source queue size | 44 |
| Scanner cases processed in source snapshot | 5 |
| Candidate findings in source snapshot | 31 |
| Revision-gated cases reviewed | 5 |
| Eligible PoC-agent cases | 4 |
| Revision-gate skips | 1 |
| Completed PoC-agent processes | 3 |
| Token-limited PoC-agent processes | 1 |
| Confirmed by completed PoC-agent | 3 |
| Confirmed by dynamic artifact with token-limited outer agent | 1 |

## Completed Or Confirmed Reviews

### 1. ActiveMQ HTTP discovery registry

- Finding ID: `csf_292e1f7d633ee069b3d50b68`
- Rule ID: `missing-auth.discovery-registry`
- Audited revision:
  `4c0d70250faed7e3739f7ef14f0d72f1625d42c1`
- Revision date: 2026-08-20
- Verdict: `CONFIRMED`.
- Evidence: unauthenticated HTTP `PUT` published an attacker-controlled broker
  endpoint into the discovery registry, the victim `DiscoveryTransport`
  consumed it, and unauthenticated HTTP `DELETE` removed it.

### 2. Artemis OpenWire durable subscription queue delete

- Finding ID: `csf_3d425881daa2c96bd9968a9d`
- Rule ID: `authorization-bypass.queue-delete`
- Audited revision:
  `a5f4979e2fe14997dcf2d5fa90cd27a6cd8f2050`
- Revision date: 2026-08-20
- Verdict: `CONFIRMED`.
- Evidence: the control core delete path rejected the attacker for missing
  `DELETE_DURABLE_QUEUE`, while OpenWire `RemoveSubscriptionInfo` deleted the
  victim durable subscription queue.

### 3. Camel FTP/SFTP remote listing path

- Finding ID: `csf_8a5accddbd0026c2a35dfc97`
- Rule ID: `path-traversal.remote-file`
- Audited revision:
  `ca11b8250b66722c69509ed5074ac5b6a6000141`
- Revision date: 2026-08-16
- Verdict: `CONFIRMED_BY_DYNAMIC_ARTIFACT`.
- Boundary: the workspace receipt and dynamic output contain
  `POC_VERDICT=CONFIRMED`, but the outer PoC-agent process exceeded its token
  budget and did not produce a normal final message.
- Evidence: a malicious listing name `a/../../../secret.txt` led to Camel's
  non-stepwise FTP path issuing `RETR poll/a/../../../secret.txt` and
  `DELE poll/a/../../../secret.txt`; the test server normalized those commands
  to `/secret.txt`, outside the configured polling directory.

### 4. Cassandra ADD IDENTITY target-role authorization

- Finding ID: `csf_9244df69ff5fc732087916e4`
- Rule ID: `authz.add-identity-target-role-control`
- Audited revision:
  `f8e301875d07b29ff840526fe03e5b4bd7567738`
- Revision date: 2026-08-19
- Verdict: `CONFIRMED`.
- Evidence: a non-superuser with only `CREATE ON ALL ROLES`, and without
  target-role control, bound an mTLS identity to an unrelated non-superuser
  role. `MutualTlsAuthenticator` then authenticated the sample certificate
  identity as the victim role. The final clean JUnit run passed with
  `tests="1"`, `errors="0"`, and `failures="0"`.

## Skipped Review

### Axis latest/default candidate

- Case: `apache_master_003`
- Repository: `apache__axis-axis1-java`
- Frozen revision:
  `2c0d66018480e0cb73d5005c99c68ef55558d2a3`
- Revision date: 2025-02-09
- Verdict: `SKIPPED_REVISION_GATE`.

Axis was not sent to PoC-agent in this pass because its default-branch latest
commit is not dated in 2026.

## Notes

- The source Codex Security snapshot still contains candidates, not verified
  vulnerabilities.
- The PoC-agent results here are evidence for the frozen latest/default
  revisions recorded by the queue.
- Vendor-reportability still needs duplicate advisory review, configuration and
  exposure review, affected release mapping, and maintainer-status review.
