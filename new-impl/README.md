# Route-Hacker New Implementation

This directory contains the current implementation modules and checked-in
experiment snapshots for Route-Hacker follow-up work.

## Modules

- `codex_security_batch/` — blind Codex Security batch runner and portable
  result snapshots.
- `poc-agent-runner/` — TraeX-based PoC verification runner and selected
  verification result snapshots.
- `guideline-agent-pipeline/` — guideline-conditioned recall to audit handoff
  scripts and model-ablation result snapshots.
- `compile-builder-v2/` — CodeQL build-repair loop.
- `runtime-v2-verifier-redesign/` — runtime builder / verifier redesign.
- `hcvr_new_unified_dataset_v2/` — unified HCVR dataset receipts.
- `repro/` — reproduction utilities and experiment harnesses.

## Experiment Result Index

| Result | Path | Contents | Status |
| --- | --- | --- | --- |
| Apache latest-default PoC-agent verification snapshot | `poc-agent-runner/results/apache-latest-default-poc-agent-20260822/` | Revision-gated PoC-agent validation for the first five latest/default Apache candidates from the 2026-08-22 progress export, including ActiveMQ, Artemis, Axis, Camel, and Cassandra rows. | Current latest/default verification snapshot; contains confirmed evidence summaries and one revision-gate skip. |
| Combined recent audit and PoC verification index | `codex_security_batch/results/combined-audit-index-20260820/` | Cross-batch summary, batch-level counts, Critical/High finding tables, completed PoC-agent outcomes, failed/interrupted/prepared run attempts, and discussion dispositions for recently validated cases including the upload/file-transfer related rows. | Current navigation index for recent scanner and PoC verification results. |
| Apache unified v2 Codex Security progress snapshot | `codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/` | `summary.md`, `summary.json`, `cases.csv`, `findings.csv` for the 40-project Apache queue; 22 terminal cases and 168 candidate findings in this snapshot. | Candidate generation snapshot; findings are not ground truth. |
| Apache unified v2 PoC-agent verification snapshot | `poc-agent-runner/results/apache-unified-v2-poc-agent-20260820/` | Triage/verification results for selected high-signal candidates from the Apache snapshot. | In progress; currently contains two ActiveMQ candidate reviews. |
| Native blind batch snapshot | `codex_security_batch/results/native-blind-batch-20260817/` | Earlier native Codex Security blind batch export. | Historical snapshot. |
| 143-case continuation snapshot | `codex_security_batch/results/143-case-through-case111-20260820/` | 143-case batch progress through case 111. | Historical/progress snapshot. |
| TraeX continuation pre-run snapshot | `codex_security_batch/results/traex-continuation-143-pre-run-20260819/` | Pre-run state for the TraeX continuation batch. | Historical/progress snapshot. |
| Guideline embedding size ablation, 30 cases | `guideline-agent-pipeline/results/model_ablation_qwen_size_30/` | Qwen embedding size comparison over the 30-case setting. | Experiment snapshot. |
| Guideline 4B full-143 ablation | `guideline-agent-pipeline/results/model_ablation_qwen4b_full143/` | Qwen3 embedding 4B full-143 ranking result. | Experiment snapshot. |

Result directories are intended to contain portable summaries and receipts only.
Do not check in source checkouts, raw agent event streams, local runtime logs, or
credentials.
