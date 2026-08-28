# GCA

Clean new implementation workspace for GCA experiments.

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
| [`143-case-final-through-case143-20260820`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/) | Final 143-case blind-audit snapshot. Earlier cases include native Codex and provider-substituted agent runs. | Complete queue: 143/143 terminal cases | [`summary.md`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/summary.md), [`cases.csv`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/cases.csv), [`findings.csv`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/findings.csv), [`GT location alignment v2`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/gt-anchor-alignment-v2-20260821/summary.md), [`full 143-case Luna adjudication`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/semantic-cve-adjudication-all143-luna-medium-20260822/summary.md), [`45-case overlap sanity check`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/semantic-cve-adjudication-luna-medium-20260821/summary.md) |
| [`143-case-through-case111-20260820`](new-impl/codex_security_batch/results/143-case-through-case111-20260820/) | Intermediate checkpoint before the final 32-case continuation. | 111/143 terminal cases | [`summary.md`](new-impl/codex_security_batch/results/143-case-through-case111-20260820/summary.md) |
| [`native-blind-batch-20260817`](new-impl/codex_security_batch/results/native-blind-batch-20260817/) | Original native Codex Security blind-batch snapshot. | Historical checkpoint | [`summary.md`](new-impl/codex_security_batch/results/native-blind-batch-20260817/summary.md) |
| Apache latest-default-branch audit | Final separate Apache discovery run. Unified v2 selects the 44 unique Apache projects; each row pins its upstream default-branch SHA rather than the historical unified-v2 source snapshot. | Complete queue: 44/44 terminal cases; 187 source-backed candidate findings. Ten scans completed cleanly, while 32 preserve partial core artifacts; one was stopped and one failed. | Stored separately from this anonymous source snapshot. |
| Apache unified-v2 project audit | Separate 44-project Apache blind-audit queue. Unified v2 contains 44 unique Apache repositories, so a 50-project Apache-only queue is unavailable without changing scope. | Paused checkpoint: 23/44 terminal queue entries; 168 candidate findings from 21 recorded scans | Stored separately from this anonymous source snapshot. |

The final snapshot contains 737 source-backed finding candidates across the 143
cases. Its broader **reported-location overlap proxy** is 45/143 (31.47%): at
least one location or code-evidence span emitted by Codex Security overlaps a GT
anchor. The artifact format does not promise that those emitted locations are a
complete call graph or an exhaustive set of related code locations. The earlier
`gt-anchor-overlap-20260820` result is a primary-location-only lower bound
(18/143). Neither proxy is a semantic CVE match or runtime confirmation, and
ground-truth alignment remains outside the blind-audit prompt.

The primary post-scan LLM-as-a-judge result covers the complete 143-case queue
using Agent CLI `GPT-5.6-Luna` with medium reasoning. For each of the 133 cases
with one or more canonical Codex Security findings, the judge received **all**
findings from that case alongside the historical CVE evidence. The other 10
cases are recorded as `no_finding_candidate`. The case-level outcomes are 40
`same_vulnerability`, 16 `related_but_different`, 64
`different_vulnerability`, 13 `insufficient_evidence`, and 10
`no_finding_candidate`. Thus the full-queue LLM-judged same-vulnerability count
is **40/143 = 27.97%**. For this one-historical-CVE-per-case benchmark, we use
this as the **direct Codex Security LLM-judged semantic accuracy**. It remains
an LLM semantic judgment rather than an independently confirmed CVE recall rate
or a runtime reproduction result.

The earlier 45-case overlap-only adjudication remains in the repository as a
historical sanity check. It must not be used as the main 143-case result.

The Apache project audit is a project-level discovery run, not a one-to-one CVE
evaluation set. Its candidates require independent source review and, where
appropriate, runtime verification before they are treated as vulnerabilities.


### Native IRIS on CWE-Bench-Java 213

The current native IRIS reproduction snapshot tracks the full 213-case
CWE-Bench-Java / IRIS universe. It records native IRIS and official CodeQL
`completed_verified` coverage, the latest 96-case CodeQL DB repair wave, the
historical r3 repair wave, and a per-case status ledger.

| Snapshot | What it contains | Status | Result files |
| --- | --- | --- | --- |
| [`iris213-cwebenchjava-status-20260824`](new-impl/repro/iris_native_agent/results/iris213-cwebenchjava-status-20260824/) | Full 213-case status snapshot for native IRIS and official CodeQL on CWE-Bench-Java. Includes the latest 96-case repair accounting, historical repair waves, final paired comparison metrics, and one row per case. | Paired completed_verified comparison: 62/213; CodeQL DB usable evidence: 93/213; latest 96 repair wave: 55 repaired and 41 no-safe. | [`summary.md`](new-impl/repro/iris_native_agent/results/iris213-cwebenchjava-status-20260824/summary.md), [`iris213_case_status.csv`](new-impl/repro/iris_native_agent/results/iris213-cwebenchjava-status-20260824/iris213_case_status.csv), [`iris213_status_summary.json`](new-impl/repro/iris_native_agent/results/iris213-cwebenchjava-status-20260824/iris213_status_summary.json) |

CodeQL DB construction is tracked as runnability/admission evidence, not as a
vulnerability detection result. Precision remains unavailable for this snapshot
because the IRIS fix-method labels are positive-only and do not define a
complete false-positive set.

### Backend-B model ablation

Paper-comparable Backend-B rows must use the same Unified V2 paper-eval
143-case set, the same recall receipt, and the same audit budget. Run the audit
stage from the local development machine, using the local Codex or Agent CLI login
and model access. Keep the configured GPU host as the recall/embedding host, then mount or
copy the recall artifacts for local audit execution.

```text
Top-K = 200 recalled anchors per case
m = 10 anchors per grouped audit prompt
groups per case = 20
```

Use `new-impl/guideline-agent-pipeline/scripts/run_hcvr_backend_b_model_queue.py`
for model rows. The only intended per-row change is `--model`.

Current artifact paths:

- Correct queue entrypoint:
  `new-impl/guideline-agent-pipeline/scripts/run_hcvr_backend_b_model_queue.py`
- Correct DeepSeek staging root:
  `/path/to/hcvr-backend-b-deepseek-flash-top200-m10-*`
  once launched with `--top-k 200 --m 10`.
- Deprecated local root:
  `/path/to/hcvr-backend-b-full143-20260820`
  was an operator-error run with `Top-K=10, m=10`. It must not be used in the
  backend-B model ablation table. It is useful only as a failure note explaining
  why Top-K and `m` must be recorded separately.

### Embedding model size ablation

Embedding-size recall experiments are separate from backend-B. Their results
live under the local/remote run roots named
`hcvr-embedding-qwen-size-runs` and should be reported as recall distribution
statistics, not bounded-audit backend metrics.
