# PoC Agent Validation Results - Codex Security Critical Findings

Source batch: `new-impl/codex_security_batch/results/native-blind-batch-20260817/findings.csv`

Run root on `bobo5090`:

`/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z`

Summary:

- Total critical findings validated: 13
- CONFIRMED: 11
- REJECTED: 2
- BLOCKED: 0

Files:

- `critical-findings-poc-summary.md`: human-readable table and reproduction commands.
- `critical-findings-poc-summary.jsonl`: machine-readable per-finding summary.
- `case-results/*-poc-result.json`: raw per-case verdict files copied from each remote PoC workspace.

Notes:

- PoC artifacts and full logs remain under the remote run root above.
- Local TraeX drove the PoC agents through `ssh bobo5090`; remote Codex was not used because the remote backend timed out during smoke checks.
- The two rejected findings were `csf_6635096ea0a669db757e59e6` and `csf_169784d9e1d69ffeee602969`.
