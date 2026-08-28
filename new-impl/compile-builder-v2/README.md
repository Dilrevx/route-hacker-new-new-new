# Compile Builder v2

Compile Builder v2 is the extracted CodeQL database build-repair loop from
GCA. It takes deterministic build failures for exact source snapshots,
asks a structured-output model to select a constrained repair decision, validates
that decision locally, and runs the resulting fresh CodeQL database attempt.

The model never supplies executable shell text. It receives a redacted failure
packet and may only select actions allowed by the packet's local policy, such as
approved Java or Maven homes, isolated dependency homes, and pre-approved build
arguments.

## Layout

- `scripts/run_codeql_llm_repair_dispatch.py`: concurrent repair controller.
- `src/gca/runtime/codeql_repair.py`: failure classification, source
  verification, decision validation, and CodeQL repair execution.
- `src/gca/runtime/bounded_process.py`: timeout-safe subprocess helper.
- `scripts/launch_deepseek_claude.sh`: optional local Claude-compatible worker
  wrapper; it expects the original host's `switch-claude` profile.
- `tests/`: unit and controller integration tests.

## Inputs

The controller requires three JSONL inputs:

1. Failed CodeQL build receipts.
2. Exact-source receipts corresponding to those failures.
3. A deterministic-repair ledger whose eligible rows have status
   `no_safe_deterministic_repair` or `repair_attempt_failed`.

Each selected case is re-bound to the failed/source receipts before the model is
called. The source revision and archive evidence are re-verified before an
attempt runs.

## Run

Use `--dry-run` to validate the receipt bindings without calling a model:

```bash
python scripts/run_codeql_llm_repair_dispatch.py \
  --failed-receipts /path/to/failed.jsonl \
  --source-receipts /path/to/sources.jsonl \
  --prior-ledger /path/to/deterministic-repair-ledger.jsonl \
  --output-dir /path/to/output \
  --expected-eligible-case-count 10 \
  --dry-run
```

For an actual repair, supply an executable that accepts the constrained
structured-output request:

```bash
python scripts/run_codeql_llm_repair_dispatch.py \
  --failed-receipts /path/to/failed.jsonl \
  --source-receipts /path/to/sources.jsonl \
  --prior-ledger /path/to/deterministic-repair-ledger.jsonl \
  --output-dir /path/to/output \
  --claude-command /path/to/claude \
  --approved-java-home /path/to/jdk-17 \
  --approved-maven-home /path/to/maven-3.9
```

Outputs are append-only JSONL receipts plus `summary.json`. Keep run outputs
outside this repository.

## Test

```bash
python -m pytest -q
```
