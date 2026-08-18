# Guideline Agent Pipeline

This module is the cleaned implementation of the simplified Route-Hacker flow:

```text
offline guideline clustering / guideline release
  -> online guideline-conditioned anchor recall
  -> per-anchor Codex harness audit
  -> audit report with risk/no-risk, confidence, and PoC handoff locations
  -> later PoC agent instrumentation and dynamic validation
```

The implementation keeps the boundary intentionally small. Retrieval proposes
anchors. The audit agent decides `risk` or `no-risk`. The PoC stage is a handoff
contract in the audit report, not a hidden reducer or schema-heavy verifier.

## Files

- `scripts/run_hcvr_case_anchor_audits.py`
  - Reads an HCVR QA receipt.
  - Selects cases from `added_identities`.
  - Consumes either dataset-provided oracle anchors or a `selected_cases.jsonl`
    produced by online guideline recall.
  - Materializes the exact source checkout in a read-only snapshot.
  - Runs one Codex audit per selected anchor.
  - Writes free-form reports plus `audit_index.jsonl` and `summary.json`.
- `scripts/recall_guideline_anchors.py`
  - Materializes exact source snapshots.
  - Mechanically cuts generic sliding-window anchor candidates from source files.
  - Embeds the guideline and candidate anchors through a real embedding backend.
  - Ranks candidates by cosine similarity and writes Top-K recall results.
  - Uses dataset anchors only after ranking to compute known-anchor Hit@K.
- `scripts/derive_guideline_from_audit.py`
  - Converts a successful risk audit report into a generalized guideline track.
  - Emits both `guideline_tracks.yaml` and a cve_clustering-style guideline
    artifact.
- `scripts/extract_poc_handoff_from_audit.py`
  - Converts completed `risk` audit rows into PoC-agent handoff packets.
  - Extracts `file:line` candidates from the report body without claiming they
    are final proof.
- `tests/`
  - Unit tests for footer parsing, command-event validation, QA case selection,
    prompt construction, and deterministic guideline derivation.

## Audit Contract

Each audit report is plain text, but it must end with exactly two
machine-readable lines:

```text
Decision: risk
Confidence: 0.90
```

or:

```text
Decision: no-risk
Confidence: 0.75
```

`unknown` is not a valid decision.

For `risk`, the body should include:

- the anchor relation;
- exact `file:line` locations for the missing or incorrect security condition;
- exact `file:line` locations for the sensitive effect;
- runtime conditions, variables, branch predicates, and state that a later PoC
  agent should observe or instrument to eliminate false positives.

## Full Guideline Recall Then Audit

This is the paper-main chain:

```text
mechanical source slicing
  -> guideline embedding recall
  -> Top-200 candidate anchors
  -> selected/reranked audit anchors
  -> per-anchor agent audit
```

`recall_guideline_anchors.py` does not use dataset anchors as ranking input.
Known anchors are used only for post-hoc Hit@K evaluation.

Start a local OpenAI-compatible embedding service when using the bundled server
from the historical route-hacker implementation:

```bash
python /Users/bytedance/workspace/route-hacker-w2-reconcile-d538b56/scripts/embedding_server.py \
  --model Qwen/Qwen3-Embedding-0.6B \
  --host 127.0.0.1 \
  --port 8001 \
  --device cuda \
  --server-batch-size 32
```

When the embedding service is on `bobo5090`, keep an SSH tunnel open in a
separate shell:

```bash
ssh -N -L 18001:127.0.0.1:8001 bobo5090
curl -sS http://127.0.0.1:18001/health
```

The health response should name `Qwen3-Embedding-0.6B` and `cuda:0`. The recall
stage uses this embedding model, not the later audit LLM.

For higher throughput on `bobo5090`, run one embedding server per GPU and open
one local tunnel per server:

```bash
for spec in 8001:0 8011:1 8002:2 8003:3 8004:4 8005:5 8006:6 8007:7; do
  port=${spec%:*}
  gpu=${spec#*:}
  nohup python scripts/embedding_server.py \
    --model /data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B \
    --host 127.0.0.1 \
    --port "$port" \
    --device "cuda:$gpu" \
    --server-batch-size 32 \
    > "logs/embedding_server_${port}.log" 2>&1 &
done

ssh -f -N -L 18001:127.0.0.1:8001 bobo5090
ssh -f -N -L 18011:127.0.0.1:8011 bobo5090
ssh -f -N -L 18002:127.0.0.1:8002 bobo5090
```

The embedding server should serialize `model.encode()` per process. Running
multiple executor threads against one SentenceTransformer instance on one GPU
can leave clients waiting on long-lived HTTP connections even when GPU
utilization has dropped. The recall client sends `Connection: close` and
retries transient HTTP 5xx, connection-refused, and timeout failures; keep
`--embedding-batch-size` modest when the service is shared. Use 32 or 64 for
large repositories before increasing the batch size.

Run real guideline-conditioned anchor recall:

```bash
RUN_ROOT=/path/to/run/hcvr-guideline-recall-top200-30
python new-impl/guideline-agent-pipeline/scripts/run_guideline_recall_queue.py \
  --qa new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --output-dir "$RUN_ROOT/recall" \
  --repo-cache "$RUN_ROOT/repo-cache" \
  --snapshot-root "$RUN_ROOT/snapshots" \
  --selection all \
  --limit 30 \
  --concurrency 8 \
  --case-timeout 1800 \
  --heartbeat-interval 30 \
  --embedding-backend openai \
  --embedding-base-url http://127.0.0.1:18001/v1 \
  --embedding-model Qwen/Qwen3-Embedding-0.6B \
  --embedding-batch-size 64 \
  --embedding-timeout 180 \
  --embedding-max-retries 3 \
  --embedding-retry-sleep 5 \
  --top-k 200
```

`run_guideline_recall_queue.py` is the preferred batch entrypoint. It runs one
case per subprocess, keeps cases from the same repository from running at the
same time, writes `events.jsonl` heartbeat records, and fails only the timed-out
case when `--case-timeout` is reached. If a shell is stuck in `WAIT`, inspect
`events.jsonl` and the per-case log under `logs/` to identify the active case
instead of treating the whole batch as hung.

Use `--limit 30` for the first smoke run. Use the full QA size only after the
30-case run has produced a `summary.json` and no repository materialization
errors remain.

Then audit the selected recalled anchor for each case. By default the recall
stage stores Top-200 candidates for evaluation and writes rank-1 into
`selected_cases.jsonl` as the audit entry point; a reranker can later consume
the Top-200 list and reduce it to a smaller Top-20/50 audit budget.

### Audit Execution Topology: Local LLM, Remote Recall

`bobo5090` is the GPU execution host for source materialization and embedding
recall. Do **not** run the LLM audit harness on that host: its Codex/TraeX and
direct provider paths are not a supported audit execution surface and can fail
because provider credentials, subscriptions, or outbound model connectivity are
unavailable. This is independent of the remote embedding service being healthy.

Current operational status: treat all AI provider paths on `bobo5090` as
unavailable for audit. In the 30-case smoke run, both
`codex exec --model DeepSeek-V4-Pro` and
`codex exec --model DeepSeek-V4-Flash` repeatedly failed with request timeouts,
including single-case, concurrency-1 probes. This is a provider/connectivity
failure, not a recall or snapshot materialization failure.

Run the audit from the local development machine, where the working Codex/TraeX
login and provider configuration live. Mount the remote run root so the local
harness consumes the exact recall output and immutable source snapshots created
on `bobo5090`; write audit outputs back into that mounted run root. For example:

```bash
# Local machine: expose the remote recall artifacts and snapshots at one path.
REMOTE_RUN=/data/lhq/workspace/hcvr-guideline-recall-top200-30
LOCAL_RUN="$HOME/tmp/hcvr-guideline-recall-top200-30"
mkdir -p "$LOCAL_RUN"
sshfs bobo5090:"$REMOTE_RUN" "$LOCAL_RUN" -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=3

# Run this command locally, not through ssh bobo5090.
LOCAL_REPO=/Users/bytedance/workspace/route-hacker-new-new
cd "$LOCAL_REPO"
python new-impl/guideline-agent-pipeline/scripts/run_hcvr_case_anchor_audits.py \
  --qa new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --selected-anchor-file "$LOCAL_RUN/recall/selected_cases.jsonl" \
  --output-dir "$LOCAL_RUN/audit" \
  --repo-cache "$LOCAL_RUN/repo-cache" \
  --snapshot-root "$LOCAL_RUN/snapshots" \
  --codex-home "$HOME/.trae" \
  --temp-root "$LOCAL_RUN/tmp-local-traex" \
  --selection all --limit 30 --codex traex --model DeepSeek-V4-Pro \
  --concurrency 8 --timeout 1500 --max-attempts 1 --clone-timeout 180 \
  --skip-materialize-failures
```

Use a locally configured model such as `DeepSeek-V4-Pro`, `GPT-5.5`, or another
known-good Codex/TraeX model. If a model is unproven, run a single-case probe
first with `--limit 1 --concurrency 1`; only scale to 30 cases after that probe
produces a valid report with the required `Decision:` and `Confidence:` footer.

When the audit ends, unmount the local mount with `umount "$LOCAL_RUN"`
(macOS) or `fusermount -u "$LOCAL_RUN"` (Linux). Keep the remote `recall/`,
`snapshots/`, per-case logs, and locally produced `audit/` outputs together
under the same run root for reproducibility.

### Recall Outputs

The recall directory contains:

```text
$RUN_ROOT/recall/
  recall_results.jsonl   # one row per case, including Top-200 anchors
  selected_cases.jsonl   # rank-N anchor rows consumed by the audit runner
  summary.json           # Hit@K, failures, candidate counts, elapsed time
  README.md              # short run summary
```

`selected_cases.jsonl` is only an audit entry-point file. It is not the full
retrieval result. Use `recall_results.jsonl` for Hit@K analysis and reranking.

### Concurrency and Repository Locks

The recall runner allows high case-level concurrency. Some QA receipts contain
multiple CVEs from the same repository, so concurrent workers can otherwise
fetch into the same `repo-cache/<repo_key>/.git` directory and collide on files
such as `.git/shallow.lock`. The runner therefore serializes only the
`ensure_snapshot()` step per `repo_key`; slicing and embedding still run in
parallel across cases.

If a previous interrupted run left a broken cache, start the next run with a
fresh `RUN_ROOT`. Do not reuse a repo cache that already reported
`.git/shallow.lock`, partial fetch, or `invalid index-pack output` errors unless
you have manually verified and repaired that repository cache.

### Common Run Modes

30-case smoke run:

```bash
RUN_ROOT=/Users/bytedance/tmp/hcvr-guideline-recall-top200-30-$(date +%Y%m%dT%H%M%S)
# run the recall command above, then the audit command above
```

Full QA receipt run:

```bash
# Same commands, but set --limit 142 or the exact intended QA count.
# Keep --top-k 200 for recall. Treat smaller budgets as rerank/audit budgets.
```

## Oracle Anchor Baseline

The audit runner without `--selected-anchor-file` uses each case's existing
`recall_anchors[--anchor-index]`. That mode is an oracle/preselected-anchor
audit baseline, not online guideline recall.

## Prepare 20 QA Cases

This prepares packets without calling Codex:

```bash
python new-impl/guideline-agent-pipeline/scripts/run_hcvr_case_anchor_audits.py \
  --qa /path/to/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --output-dir /path/to/run/prepared20 \
  --repo-cache /path/to/run/repo-cache \
  --snapshot-root /path/to/run/snapshots \
  --codex-home ~/.codex \
  --temp-root /path/to/tmp \
  --limit 20 \
  --prepare-only
```

Use `--no-materialize` with `--prepare-only` when you only want prompt packets
and do not want to clone repositories yet.

## Run Codex Harness Audits

The default model is `qwen3-coder:30b`, matching the successful OpenMeetings
pilot harness. Run this section from the local machine with a working
Codex/TraeX provider configuration. If snapshots and recall outputs were built
on `bobo5090`, mount their run root as described above; do not rely on LLM
provider configuration on `bobo5090`.

```bash
python new-impl/guideline-agent-pipeline/scripts/run_hcvr_case_anchor_audits.py \
  --qa /path/to/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --output-dir /path/to/run/audit20 \
  --repo-cache /path/to/run/repo-cache \
  --snapshot-root /path/to/run/snapshots \
  --codex-home ~/.codex \
  --temp-root /path/to/tmp \
  --limit 20 \
  --concurrency 1 \
  --timeout 900 \
  --max-attempts 1
```

Outputs:

```text
/path/to/run/audit20/
  selected_cases.jsonl
  audit_index.jsonl
  summary.json
  reports/
    <case>.prompt.txt
    <case>.attempt-01.events.jsonl
    <case>.attempt-01.md
    <case>.events.jsonl
    <case>.md
```

The runner starts Codex in its own process group. If a timeout fires, it kills
the full process group so native Codex children do not remain orphaned.

## Seed a New Guideline from a Risk Audit

```bash
python new-impl/guideline-agent-pipeline/scripts/derive_guideline_from_audit.py \
  --audit-report /path/to/reports/rank-0020.md \
  --output-dir /path/to/derived-guideline \
  --track-id object_scoped_authorization_after_interface_permission
```

The derived guideline intentionally excludes project names, file names,
function names, and line numbers from the released guideline text.

## PoC Handoff

The PoC agent is downstream of this module. It should consume risk reports and
use the report body to choose instrumentation points. This module does not run
dynamic PoCs itself.

Recommended handoff fields are already present in the report text:

- anchor `file:line`;
- missing or incorrect condition `file:line`;
- sensitive effect `file:line`;
- branch predicates and variables to observe;
- expected runtime state that distinguishes true risk from false positive.

Build handoff packets from completed audit results:

```bash
python new-impl/guideline-agent-pipeline/scripts/extract_poc_handoff_from_audit.py \
  --audit-index /path/to/run/audit20/audit_index.jsonl \
  --output /path/to/run/audit20/poc_handoff.jsonl
```

## Test

```bash
python -m pytest -q new-impl/guideline-agent-pipeline/tests
```

## Operational Notes

- Keep run outputs outside the repository.
- Do not commit cloned repositories, snapshots, Codex logs, prompts from private
  code, credentials, or auth state.
- Use the QA receipt and source snapshots as inputs, not training data or
  hidden truth during audit.
- Recall Top-K and audit concurrency are separate knobs. The recommended first
  pass is recall `--top-k 200` and audit `--concurrency 8`.
- The recall stage uses the embedding service endpoint. The audit stage uses
  the locally configured `--model` passed to
  `run_hcvr_case_anchor_audits.py`, for example `DeepSeek-V4-Pro`. The remote
  host is not an LLM provider fallback.
- The local macOS system Python may not have `pytest`. In that case,
  `python3 -m py_compile scripts/recall_guideline_anchors.py` is still a quick
  syntax check, but full tests require an environment with `pytest` installed.
