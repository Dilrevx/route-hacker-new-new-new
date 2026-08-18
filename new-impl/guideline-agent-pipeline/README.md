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

Start a local OpenAI-compatible embedding service when using the bundled server
from the historical route-hacker implementation:

```bash
python /Users/bytedance/workspace/route-hacker-w2-reconcile-d538b56/scripts/embedding_server.py \
  --model Qwen/Qwen3-Embedding-0.6B \
  --host 127.0.0.1 \
  --port 8001 \
  --device cuda
```

Run real guideline-conditioned anchor recall:

```bash
python new-impl/guideline-agent-pipeline/scripts/recall_guideline_anchors.py \
  --qa new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --output-dir /path/to/run/recall142 \
  --repo-cache /path/to/run/repo-cache \
  --snapshot-root /path/to/run/snapshots \
  --selection all \
  --limit 142 \
  --case-workers 16 \
  --embedding-backend openai \
  --embedding-base-url http://127.0.0.1:8001/v1 \
  --embedding-model Qwen/Qwen3-Embedding-0.6B \
  --embedding-batch-size 128 \
  --top-k 30
```

Then audit the recalled Top-1 anchor for each case:

```bash
python new-impl/guideline-agent-pipeline/scripts/run_hcvr_case_anchor_audits.py \
  --qa new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --selected-anchor-file /path/to/run/recall142/selected_cases.jsonl \
  --output-dir /path/to/run/audit142-recalled \
  --repo-cache /path/to/run/repo-cache \
  --snapshot-root /path/to/run/snapshots \
  --codex-home ~/.trae \
  --temp-root /path/to/tmp \
  --selection all \
  --limit 142 \
  --codex traex \
  --model DeepSeek-V4-Flash \
  --concurrency 16 \
  --timeout 1500 \
  --max-attempts 1 \
  --clone-timeout 180 \
  --skip-materialize-failures
```

This is the paper-main chain:

```text
mechanical source slicing
  -> guideline embedding recall
  -> selected Top-K anchors
  -> per-anchor agent audit
```

`recall_guideline_anchors.py` does not use dataset anchors as ranking input.
Known anchors are used only for post-hoc Hit@K evaluation.

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
pilot harness.

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
