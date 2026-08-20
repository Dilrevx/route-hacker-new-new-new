# route-hacker-new

Clean new implementation workspace for Route-Hacker experiments.

Current module: `new-impl/codex_security_batch/` contains the Codex Security blind batch runner and its module README.

## Experiment results index

This repository keeps portable experiment snapshots under each module's `results/`
directory. Snapshots contain aggregate summaries and tabular outputs, but exclude
credentials, local checkouts, logs, and other machine-specific runtime state.

### Codex Security blind audit on HCVR unified v2

The current completed baseline runs Codex Security as a full-repository blind
audit over the 143 fixed revisions in the HCVR unified v2 evaluation queue. The
scanner was not given CVE names, vulnerability types, source/sink locations,
patches, or target files. Dataset metadata is retained only for offline
evaluation after scanning.

| Snapshot | What it contains | Status | Result files |
| --- | --- | --- | --- |
| [`143-case-final-through-case143-20260820`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/) | Final 143-case blind-audit snapshot. Earlier cases include native Codex and provider-substituted TraeX runs; the final continuation uses TraeX with GPT-5.4 high. | Complete queue: 143/143 terminal cases | [`summary.md`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/summary.md), [`cases.csv`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/cases.csv), [`findings.csv`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/findings.csv) |
| [`143-case-through-case111-20260820`](new-impl/codex_security_batch/results/143-case-through-case111-20260820/) | Intermediate checkpoint before the final 32-case continuation. | 111/143 terminal cases | [`summary.md`](new-impl/codex_security_batch/results/143-case-through-case111-20260820/summary.md) |
| [`traex-continuation-143-pre-run-20260819`](new-impl/codex_security_batch/results/traex-continuation-143-pre-run-20260819/) | Earlier TraeX continuation checkpoint. | Historical checkpoint | [`summary.md`](new-impl/codex_security_batch/results/traex-continuation-143-pre-run-20260819/summary.md) |
| [`native-blind-batch-20260817`](new-impl/codex_security_batch/results/native-blind-batch-20260817/) | Original native Codex Security blind-batch snapshot. | Historical checkpoint | [`summary.md`](new-impl/codex_security_batch/results/native-blind-batch-20260817/summary.md) |

The final snapshot contains 737 source-backed finding candidates across the 143
cases. These are not yet ground-truth CVE matches or runtime-confirmed
vulnerabilities. A separate offline evaluator must join a finding's path and
line range with the unified-v2 recall anchors, then report the target-CVE
hit-rate; that evaluation must remain outside the blind-audit prompt.
