# Apache Latest-Default PoC-Agent Verification Snapshot

This snapshot tracks the first five Apache latest/default Codex Security
candidates from the 2026-08-22 progress export.

- Source snapshot:
  `new-impl/codex_security_batch/results/apache-unified-v2-latest-default-gpt55-high-progress-20260822/`
- Source branch snapshot commit:
  `cee863c Fix timeout helper executable mode`
- Queue size: 44 Apache latest/default project audits
- Processed scanner cases in source snapshot: 5
- Candidate findings in source snapshot: 31
- PoC-agent model: `gpt-5.5` / `high`

The revision gate for this new-project false-positive audit workflow is:
run PoC validation only when the target repository's frozen latest/default
branch commit is dated in 2026. Raw TraeX event streams, prompts, source
checkouts, local temporary workspaces, and credentials are intentionally
excluded from this committed snapshot.

## Current Results

| Case | Repository | Candidate | Frozen revision | Revision gate | PoC status | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `apache_master_001` | `apache__activemq` | Unauthenticated HTTP discovery registry permits arbitrary broker endpoint publication and removal | `4c0d70250faed7e3739f7ef14f0d72f1625d42c1` | eligible, 2026-08-20 | completed | `CONFIRMED` |
| `apache_master_002` | `apache__activemq-artemis` | OpenWire RemoveSubscriptionInfo can delete durable subscription queues without SecurityStore authorization | `a5f4979e2fe14997dcf2d5fa90cd27a6cd8f2050` | eligible, 2026-08-20 | completed | `CONFIRMED` |
| `apache_master_003` | `apache__axis-axis1-java` | Axis latest/default candidate | `2c0d66018480e0cb73d5005c99c68ef55558d2a3` | skipped, 2025-02-09 | not run | `SKIPPED_REVISION_GATE` |
| `apache_master_004` | `apache__camel` | FTP and SFTP consumers trust remote listing names for read, delete, and rename paths | `ca11b8250b66722c69509ed5074ac5b6a6000141` | eligible, 2026-08-16 | outer agent token-limited after writing PoC artifacts | `CONFIRMED_BY_DYNAMIC_ARTIFACT` |
| `apache_master_005` | `apache__cassandra` | ADD IDENTITY authorizes global role creation instead of target-role control | `f8e301875d07b29ff840526fe03e5b4bd7567738` | eligible, 2026-08-19 | completed | `CONFIRMED` |

## Files

- `verification-summary.md` - concise batch verification summary.
- `cases.csv` - machine-readable revision-gate and PoC outcome rows.
- `evidence-snippets.md` - sanitized evidence markers from the completed local
  and remote PoC runs.

## Notes

- These rows validate the queue's frozen latest/default revisions, not a live
  remote HEAD re-resolution at read time.
- `CONFIRMED` means the PoC-agent produced a reproducible local or remote
  runtime artifact matching the candidate's reported security effect.
- `CONFIRMED_BY_DYNAMIC_ARTIFACT` means the dynamic artifact and receipt contain
  confirmation evidence, but the outer PoC-agent process hit its token budget
  before writing a normal final message.
- Vendor disclosure still needs a separate current-release impact, duplicate
  advisory, configuration exposure, and maintainership review.
