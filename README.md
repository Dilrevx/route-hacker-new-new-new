# route-hacker-new

Clean new implementation workspace for Route-Hacker experiments.

Current module: `new-impl/codex_security_batch/` contains the Codex Security blind batch runner and its module README.

## Experiment results index

The paths below are committed result snapshots and can be opened from a fresh
clone. They intentionally exclude credentials, local source checkouts, raw
scanner logs, and absolute artifact paths. A Codex Security finding is a
candidate until source review and, where appropriate, runtime verification.

| Experiment | Scope and current status | Committed outputs |
| --- | --- | --- |
| Apache latest-default PoC-agent verification snapshot | First five latest/default Apache candidates from the 2026-08-22 progress export, gated by the 2026 latest/default commit rule. Four eligible cases entered PoC-agent validation: ActiveMQ, Artemis, Camel, and Cassandra. Axis was skipped because its frozen default-branch revision is from 2025. | [summary](new-impl/poc-agent-runner/results/apache-latest-default-poc-agent-20260822/verification-summary.md), [cases](new-impl/poc-agent-runner/results/apache-latest-default-poc-agent-20260822/cases.csv), [evidence snippets](new-impl/poc-agent-runner/results/apache-latest-default-poc-agent-20260822/evidence-snippets.md), [README](new-impl/poc-agent-runner/results/apache-latest-default-poc-agent-20260822/README.md) |
| Combined recent audit and PoC verification index | Cross-batch index for the recent 143-case snapshots, Apache unified-v2 project audit, Axis latest-HEAD smoke run, and recovered PoC-agent verification outcomes. It records alert totals, Critical/High rows, completed PoC-agent verdicts, failed or interrupted attempts, and later discussion dispositions such as duplicate, historical-only, wrong-effect, or likely-not-reportable. | [summary](new-impl/codex_security_batch/results/combined-audit-index-20260820/summary.md), [batch table](new-impl/codex_security_batch/results/combined-audit-index-20260820/batches.csv), [representative Critical/High findings](new-impl/codex_security_batch/results/combined-audit-index-20260820/representative_critical_high_findings.csv), [PoC outcomes](new-impl/codex_security_batch/results/combined-audit-index-20260820/poc_agent_outcomes.csv), [run attempts](new-impl/codex_security_batch/results/combined-audit-index-20260820/poc_agent_run_attempts.csv) |
| Apache unified-v2 blind audit (paused) | Unified v2 contains 44 unique Apache repositories at fixed dataset revisions, scanned with Codex Security using `gpt-5.5` / `high`; a 50-project Apache-only queue is therefore unavailable without changing scope. The current checkpoint covers 23 terminal queue entries: 4 accepted, 17 with partial artifacts, and 2 explicitly stopped after stalls. It reports 168 candidate findings from 21 recorded scans. The runner is paused while its queue scheduling is hardened; only committed files are authoritative for this row. | [summary](new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/summary.md), [per-project status](new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/cases.csv), [finding candidates](new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/findings.csv), [machine-readable summary](new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/summary.json) |
| Native blind batch baseline | Earlier HCVR blind-audit snapshot. This is separate from the Apache project queue. | [summary](new-impl/codex_security_batch/results/native-blind-batch-20260817/summary.md), [cases](new-impl/codex_security_batch/results/native-blind-batch-20260817/cases.csv), [findings](new-impl/codex_security_batch/results/native-blind-batch-20260817/findings.csv) |
| 143-case continuation snapshot | Earlier 143-case continuation snapshot; use it for historical comparison only. | [summary](new-impl/codex_security_batch/results/143-case-through-case111-20260820/summary.md), [cases](new-impl/codex_security_batch/results/143-case-through-case111-20260820/cases.csv), [findings](new-impl/codex_security_batch/results/143-case-through-case111-20260820/findings.csv) |
| TraeX continuation pre-run | Pre-run checkpoint for the 143-case TraeX continuation. | [summary](new-impl/codex_security_batch/results/traex-continuation-143-pre-run-20260819/summary.md), [cases](new-impl/codex_security_batch/results/traex-continuation-143-pre-run-20260819/cases.csv), [findings](new-impl/codex_security_batch/results/traex-continuation-143-pre-run-20260819/findings.csv) |

### Apache audit workflow

`new-impl/codex_security_batch/build_apache_unified_v2_queue.py` deterministically
selects Apache repositories from unified v2, de-duplicates by repository, and
emits the project-level blind-audit queue. The default limit is 30; the full
Apache-only selection contains 44 unique repositories.

The current Apache checkpoint uses the full 44-project queue with SHA-256
`7e22ecdd90ec13fdbe221ee3244ff8cb91e8ea3384c30eb10118a0c4e613b447`.

### Recent `apache-audit` branch additions

- `06ea64a` — added the reproducible Apache unified-v2 queue builder.
- `dac7e7e` — added the portable Apache progress snapshot and made the batch
  summarizer compatible with project-level queues that intentionally omit a
  one-to-one vulnerability identifier.
