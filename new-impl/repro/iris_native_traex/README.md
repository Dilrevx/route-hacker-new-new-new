# Native IRIS With Local TraeX

This reproduction preserves IRIS's original analysis flow:

1. extract external APIs and internal parameters with CodeQL;
2. use an LLM to label source, sink, taint-propagator, and function-parameter candidates;
3. generate and run IRIS's project-specific CodeQL query;
4. run IRIS's postprocessing and LLM posthoc filter;
5. run IRIS's evaluator.

The only adaptation is the LLM transport. `serve_traex_openai.py` exposes the local
`traex exec -m DeepSeek-V4-Flash` or `DeepSeek-V4-Pro` command as the small OpenAI
Chat Completions subset consumed by IRIS's existing `GPTModel`. Each isolated IRIS
copy receives two transport-only model aliases, `gpt-traex-flash` and
`gpt-traex-pro`, which resolve to the local TraeX models. It does not classify
cases, generate CodeQL rules, or replace any IRIS stage.

When started with `--metrics-log`, the bridge records one JSONL row per completed
or failed local TraeX call. Each row includes the model, IRIS case/run attribution,
elapsed seconds, response digest, and `traex_reported_total_tokens` when the CLI
prints a token count. This is the CLI's reported total, not an inferred
input/output-token split.

## Inputs

The scripts expect:

- a clean, pinned IRIS root containing `src/` and metadata CSV files;
- a CodeQL distribution compatible with that IRIS root;
- an audited IRIS layout receipt JSONL with either `iris_shadow_root_ready`
  rows or strict-admission rows that pass the official IRIS metadata checks;
- each ready receipt's exact source tree, CodeQL DB, and package-name file.

For current unified-v2 evaluation, first convert strict-admission evidence plus
the current CodeQL denominator manifest into a native-IRIS queue:

```bash
python3 scripts/prepare_current_v2_iris_queue.py \
  --current-review /path/hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl \
  --codeql-manifest /path/current_143_with_usable_codeql_db_manifest.jsonl \
  --strict-admission /path/strict-admission.jsonl \
  --iris213-case-status /path/iris213_case_status.csv \
  --out-dir /path/current-v2-iris-queue
```

The queue uses CVE/GHSA plus checkout revision alignment. It writes
`current_v2_native_iris_ready_queue.jsonl`, which can be passed directly to the
batch runner.

These inputs remain external to Git. Outputs, source snapshots, DBs, and model
credentials are never committed.

## Single-Case Smoke

On the local machine, start the bridge:

```bash
python3 scripts/serve_traex_openai.py \
  --port 18888 \
  --model DeepSeek-V4-Pro \
  --max-concurrency 2 \
  --metrics-log /path/to/traex_calls.jsonl
```

Expose it to the remote IRIS host with a reverse SSH tunnel:

```bash
ssh -N -R 127.0.0.1:18888:127.0.0.1:18888 bobo5090
```

On the remote host, materialize a fresh case workspace and execute it:

```bash
python3 scripts/materialize_iris_case.py \
  --receipts /path/clean_iris_shadow_root_receipts.v1.jsonl \
  --case-id square__retrofit_CVE-2018-1000850_2.4.0 \
  --clean-iris-root /path/clean-iris-root \
  --codeql-dir /path/codeql \
  --workspace /mnt/.../iris-native-traex/retrofit

python3 scripts/run_native_iris_case.py \
  --workspace /mnt/.../iris-native-traex/retrofit \
  --run-id native-traex-retrofit-v1 \
  --bridge-url http://127.0.0.1:18888 \
  --llm-timeout-seconds 300 \
  --output-dir /mnt/.../iris-native-traex/results/retrofit
```

The runner succeeds when native IRIS exits zero and all final IRIS artifacts
exist. Raw LLM label responses that do not parse cleanly are retained as
completion warnings because native IRIS may still recover enough structure to
finish the pipeline.

## Bounded Batch

After a single case succeeds, start with `--max-workers 2` and increase only
within the bridge's configured concurrency. `run_native_iris_batch.py` writes a
receipt for every attempt and supports `--resume`. Its `--attempt-id` creates a
fresh namespace for materialized workspaces and IRIS output. Keep the same
attempt ID for resume; choose a new one when intentionally retrying failed
cases with an updated environment.

```bash
python3 scripts/run_native_iris_batch.py \
  --attempt-id flash-a1 \
  --max-workers 2 \
  --llm-timeout-seconds 300 \
  --resume ...
```

Each batch receipt stores IRIS candidate, labelling, vanilla-path, posthoc-path,
method-overlap, elapsed-time, artifact-gate, and label-response fields. The
dispatcher updates `summary.json` after each completed case.

After a batch, merge the receipt and bridge JSONL files into a paper-facing
report. It carries per-case output paths and aggregate candidate/path metrics,
bridge-call status, and TraeX-reported total tokens without inventing an
input/output split:

```bash
python3 scripts/summarize_native_iris_metrics.py \
  --receipt-ledger /path/results/receipts.jsonl \
  --bridge-metrics /path/traex_calls.jsonl \
  --output /path/results/paper_metrics.json
```
