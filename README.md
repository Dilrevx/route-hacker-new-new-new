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
| [`143-case-final-through-case143-20260820`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/) | Final 143-case blind-audit snapshot. Earlier cases include native Codex and provider-substituted TraeX runs; the final continuation uses TraeX with GPT-5.4 high. | Complete queue: 143/143 terminal cases | [`summary.md`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/summary.md), [`cases.csv`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/cases.csv), [`findings.csv`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/findings.csv), [`GT location alignment v2`](new-impl/codex_security_batch/results/143-case-final-through-case143-20260820/gt-anchor-alignment-v2-20260821/summary.md) |
| [`143-case-through-case111-20260820`](new-impl/codex_security_batch/results/143-case-through-case111-20260820/) | Intermediate checkpoint before the final 32-case continuation. | 111/143 terminal cases | [`summary.md`](new-impl/codex_security_batch/results/143-case-through-case111-20260820/summary.md) |
| [`traex-continuation-143-pre-run-20260819`](new-impl/codex_security_batch/results/traex-continuation-143-pre-run-20260819/) | Earlier TraeX continuation checkpoint. | Historical checkpoint | [`summary.md`](new-impl/codex_security_batch/results/traex-continuation-143-pre-run-20260819/summary.md) |
| [`native-blind-batch-20260817`](new-impl/codex_security_batch/results/native-blind-batch-20260817/) | Original native Codex Security blind-batch snapshot. | Historical checkpoint | [`summary.md`](new-impl/codex_security_batch/results/native-blind-batch-20260817/summary.md) |
| [Apache unified-v2 project audit](https://github.com/Dilrevx/route-hacker-new-new/tree/apache-audit/new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820) | Separate 44-project Apache blind-audit queue using native Codex Security with GPT-5.5/high. Unified v2 contains 44 unique Apache repositories, so a 50-project Apache-only queue is unavailable without changing scope. This portable snapshot lives on the `apache-audit` branch until it is explicitly merged. | Paused checkpoint: 23/44 terminal queue entries; 168 candidate findings from 21 recorded scans | [summary](https://github.com/Dilrevx/route-hacker-new-new/blob/apache-audit/new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/summary.md), [cases](https://github.com/Dilrevx/route-hacker-new-new/blob/apache-audit/new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/cases.csv), [findings](https://github.com/Dilrevx/route-hacker-new-new/blob/apache-audit/new-impl/codex_security_batch/results/apache-unified-v2-gpt55-high-progress-20260820/findings.csv) |

The final snapshot contains 737 source-backed finding candidates across the 143
cases. Its main offline alignment reports 45/143 (31.47%) cases where at least
one Codex Security reported location or code-evidence span overlaps a GT anchor.
The earlier `gt-anchor-overlap-20260820` result is retained as a primary-location
only lower bound (18/143), not the main metric. These are localization proxies,
not semantic CVE matches or runtime-confirmed vulnerabilities. Ground-truth
alignment remains outside the blind-audit prompt.

The Apache project audit is a project-level discovery run, not a one-to-one CVE
evaluation set. Its candidates require independent source review and, where
appropriate, runtime verification before they are treated as vulnerabilities.

### Backend-B model ablation

Paper-comparable Backend-B rows must use the same Unified V2 paper-eval
143-case set, the same recall receipt, and the same audit budget. Run the audit
stage from the local development machine, using the local Codex or TraeX login
and model access. Keep `bobo5090` as the recall/embedding host, then mount or
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
  `/Users/bytedance/tmp/hcvr-backend-b-deepseek-flash-top200-m10-*`
  once launched with `--top-k 200 --m 10`.
- Deprecated local root:
  `/Users/bytedance/tmp/hcvr-backend-b-full143-20260820`
  was an operator-error run with `Top-K=10, m=10`. It must not be used in the
  backend-B model ablation table. It is useful only as a failure note explaining
  why Top-K and `m` must be recorded separately.

### Embedding model size ablation

Embedding-size recall experiments are separate from backend-B. Their results
live under the local/remote run roots named
`hcvr-embedding-qwen-size-runs` and should be reported as recall distribution
statistics, not bounded-audit backend metrics.
