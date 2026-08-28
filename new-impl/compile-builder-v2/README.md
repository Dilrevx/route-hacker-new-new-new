# Compile Builder v2

Compile Builder v2 implements GCA's bounded CodeQL database build-repair loop.
It receives deterministic build failures for pinned source snapshots, asks a
structured-output model to select a constrained repair action, validates that
action locally, and performs a fresh database attempt.

The model never supplies executable shell text. It may select only actions
allowed by the local policy, such as an approved toolchain, isolated dependency
home, predeclared build argument, or bounded resource adjustment.

## Layout

- `scripts/run_codeql_llm_repair_dispatch.py`: concurrent repair controller.
- `src/gca/runtime/codeql_repair.py`: failure classification, source
  verification, action validation, and repair execution.
- `src/gca/runtime/bounded_process.py`: timeout-safe process helper.
- `tests/`: unit and controller integration tests.

## Inputs and Outputs

The controller consumes failed-build receipts, exact-source receipts, and a
prior deterministic-repair ledger. It rebinds every selected case to those
receipts and verifies the source revision before execution.

Outputs are append-only JSONL receipts plus an aggregate `summary.json`.
Source trees, CodeQL databases, model credentials, and per-case logs remain
outside Git.

## Example Shape

```bash
python scripts/run_codeql_llm_repair_dispatch.py \
  --failed-receipts /path/to/failed.jsonl \
  --source-receipts /path/to/sources.jsonl \
  --prior-ledger /path/to/repair-ledger.jsonl \
  --output-dir /path/to/output \
  --dry-run
```

For an actual repair, provide a configured structured-output model command and
the locally approved toolchain paths. Use `--help` for the complete policy and
resource options.

## Testing

```bash
python -m pytest -q tests
```
