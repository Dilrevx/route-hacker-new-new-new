# Codex Security Blind Batch Runner

This module runs native Codex Security full-repository blind audits over an HCVR
case queue. It is the cleaned version of the ad hoc runner used for the 2026-08
Codex Security feasibility batch.

The runner prepares each target repository at the dataset revision, invokes
`@openai/codex-security scan` on the whole repository, and records local status,
logs, output artifact paths, finding counts, and coverage summaries.

## Scope

The queue and runner intentionally use only scheduling metadata:

- `case_id`
- `repo_key`
- `repo_url`
- `checkout_revision`
- `vulnerability_type`

They do not pass dataset target files, source/sink locations, anchors, known
findings, patch hunks, or ground-truth lines into Codex Security. Each scan is a
full-repository blind audit.

## Files

- `build_blind_queue.py` converts an HCVR QA receipt JSON/JSONL file into the
  blind queue format.
- `run_blind_batch.sh` executes the queue, tracks state markers, and appends
  `run_records.jsonl`.
- `summarize_blind_batch.py` joins the queue to the latest per-case record and
  produces a portable result snapshot without credentials, logs, source trees,
  or absolute artifact paths.

## Build a Queue

Example with the current HCVR v2 QA receipt:

```bash
python new-impl/codex_security_batch/build_blind_queue.py \
  --qa /data/lhq/workspace/route-hacker-lineage-integration-20260803/assets/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --out /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/codex-security-143/control/queue.jsonl
```

The queue builder validates the emitted queue for leaky field names. If the
source receipt schema changes, update the field extraction logic and keep the
output restricted to scheduling metadata.

By default the builder emits the full allowlist referenced by the receipt. To
restrict the queue to cases marked usable for fix-revision evidence:

```bash
python new-impl/codex_security_batch/build_blind_queue.py \
  --qa /data/lhq/workspace/route-hacker-lineage-integration-20260803/assets/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --out /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/codex-security-143/control/queue.usable.jsonl \
  --usable-fix-revision-only
```

## Run with Native Codex

Native Codex Security is the default mode. The command below runs two outer
workers and starts at most ten new cases:

```bash
export CODEX_SECURITY_RUN_ROOT=/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/codex-security-143
export CODEX_SECURITY_QUEUE=$CODEX_SECURITY_RUN_ROOT/control/queue.jsonl
export CODEX_SECURITY_MODEL=gpt-5.6-terra
export CODEX_SECURITY_EFFORT=high
export CODEX_SECURITY_OUTER_PARALLELISM=2
export CODEX_SECURITY_MAX_NEW_CASES=10
# Per-case wall-clock limit; default is 43200 seconds (12 hours).
export CODEX_SECURITY_CASE_TIMEOUT_SECONDS=43200

bash new-impl/codex_security_batch/run_blind_batch.sh
```

The scanner command is:

```bash
npx -y @openai/codex-security@0.1.12 scan <prepared-repo> \
  --model "$CODEX_SECURITY_MODEL" \
  --effort "$CODEX_SECURITY_EFFORT" \
  --headless \
  --verbose \
  --archive-existing \
  --output-dir <attempt-output-dir>
```

## Run with a Local TraeX Wrapper

For local cost experiments, Codex Security can be pointed at a Codex-compatible
wrapper that dispatches the inner agent call through TraeX. The wrapper must be
provided by the local environment; this module does not store credentials,
tokens, or generated login state.

For the Apache latest-default-branch queue, use the dedicated launcher with
`CODEX_SECURITY_NATIVE_CASES=0` when native Codex quota is unavailable. This
skips native work and schedules every non-terminal queue row through the TraeX
wrapper; it never waits behind a native phase barrier.

```bash
export CODEX_SECURITY_RUN_ROOT=/path/to/apache-latest-default-run
export CODEX_SECURITY_QUEUE=$CODEX_SECURITY_RUN_ROOT/control/queue.jsonl
export CODEX_SECURITY_MODEL=gpt-5.5
export CODEX_SECURITY_EFFORT=high
export CODEX_SECURITY_OUTER_PARALLELISM=4
export CODEX_SECURITY_CASE_TIMEOUT_SECONDS=43200
export CODEX_SECURITY_NATIVE_CASES=0
export CODEX_SECURITY_WRAPPER=/path/to/codex-security-traex-wrapper.sh
export CODEX_SECURITY_TRAEX_BIN=/path/to/traex
export CODEX_SECURITY_PLUGIN_DIR=/path/to/codex-security/_bundled_plugin

bash new-impl/codex_security_batch/run_latest_default_branch_phased.sh
```

```bash
export CODEX_SECURITY_USE_TRAEX_WRAPPER=1
export CODEX_SECURITY_WRAPPER=/path/to/codex-security-traex-plugin-aware-wrapper.sh
export CODEX_SECURITY_TRAEX_BIN=/Users/bytedance/.local/bin/traex
export CODEX_SECURITY_PLUGIN_DIR=/path/to/@openai/codex-security/_bundled_plugin

bash new-impl/codex_security_batch/run_blind_batch.sh
```

Use this mode only when the wrapper preserves the Codex Security prompt and
plugin behavior closely enough for the experiment being measured.

## Runtime Layout

With `CODEX_SECURITY_RUN_ROOT=/path/to/run`, the module writes:

```text
/path/to/run/
  control/
    queue.jsonl
    status.tsv
    run_records.jsonl
    logs/<case_id>.log
    logs/<case_id>.log.header
    state/<case_id>.<state>
  runtime/
    repo-cache/
    batch/
      inputs/<case_id>/repo/
      outputs/<case_id>/<attempt_id>/
```

Terminal states are `accepted`, `partial`, `failed`, and `stopped`. Active or
intermediate states are `running` and `prepared`.

`partial` means Codex Security returned a non-zero exit code but produced the
core artifacts `scan-manifest.json`, `findings.json`, and `coverage.json`.

## Status Refresh

To refresh `status.tsv` without starting scans:

```bash
CODEX_SECURITY_STATUS_ONLY=1 \
CODEX_SECURITY_RUN_ROOT=/path/to/run \
CODEX_SECURITY_QUEUE=/path/to/run/control/queue.jsonl \
bash new-impl/codex_security_batch/run_blind_batch.sh
```

## Export a Result Snapshot

The runner may append multiple records for retried cases. The summarizer keeps
the latest record for each `case_id`, preserves the scheduler's terminal state,
and extracts finding metadata from the canonical Codex Security artifacts.

```bash
python new-impl/codex_security_batch/summarize_blind_batch.py \
  --queue /path/to/run/control/queue.jsonl \
  --records /path/to/run/control/run_records.jsonl \
  --state-dir /path/to/run/control/state \
  --log-dir /path/to/run/control/logs \
  --out-dir /path/to/result-snapshot
```

The output contains:

- `summary.json`: aggregate counts and integrity hashes.
- `summary.md`: concise human-readable report.
- `cases.csv`: the ordered full queue with terminal status, model, coverage,
  findings, producer, and artifact-presence metadata.
- `findings.csv`: one row per Codex Security finding candidate.

Dataset vulnerability IDs and types in these exports are evaluation joins. They
are not passed into the repository-level blind audit prompt.

The current checked-in snapshot is under
`results/native-blind-batch-20260817/`.

## Guards

The runner creates sentinels under `control/state/` and refuses to continue
unless explicitly overridden:

- `quota_blocked` when the Codex log reports a usage limit
- `auth_blocked` when the Codex log reports refresh-token/auth failures

Override only after diagnosis:

```bash
export CODEX_SECURITY_CONTINUE_AFTER_USAGE_LIMIT=1
export CODEX_SECURITY_CONTINUE_AFTER_AUTH_ERROR=1
```

## Operational Notes

- Keep run roots outside the git repository.
- Do not commit `control/`, `runtime/`, scanner outputs, or auth material.
- Use `CODEX_SECURITY_MAX_NEW_CASES` for budgeted top-ups.
- Use `CODEX_SECURITY_OUTER_PARALLELISM=2` as the current practical default.
- The default `CODEX_SECURITY_CASE_TIMEOUT_SECONDS=43200` gives each case a
  12-hour wall-clock limit. On timeout, the runner terminates the scan process
  group, preserves any emitted artifacts, and continues with the next queue
  entry.
- Preserve output attempts and logs; they are the audit evidence trail.
