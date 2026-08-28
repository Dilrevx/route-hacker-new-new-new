# Native IRIS Baseline Harness

This module adapts IRIS to a local agent-compatible model endpoint while
preserving IRIS's native analysis flow:

1. extract external APIs and internal parameters with CodeQL;
2. label source, sink, propagator, and parameter candidates;
3. generate and run the project-specific CodeQL query;
4. apply IRIS postprocessing and post-hoc filtering;
5. evaluate the resulting paths.

The adaptation changes model transport only. It does not synthesize replacement
queries, classify cases outside IRIS, or change the evaluator.

## Programs

- `scripts/serve_agent_openai.py` exposes a small OpenAI-compatible chat
  endpoint backed by a configured local agent command.
- `scripts/materialize_iris_case.py` creates an isolated IRIS workspace from
  an admitted source and CodeQL receipt.
- `scripts/run_native_iris_case.py` executes one native IRIS case.
- `scripts/run_native_iris_batch.py` executes a resumable queue.
- `scripts/prepare_current_v2_iris_queue.py` joins admitted source and CodeQL
  inputs into a batch manifest.
- `scripts/summarize_native_iris_metrics.py` produces aggregate accounting.

## External Inputs

The harness expects a clean pinned IRIS checkout, a compatible CodeQL
distribution, exact source snapshots, and usable database receipts. These
inputs, model credentials, generated workspaces, raw responses, and per-case
outputs remain outside Git.

## Example Shape

```bash
python scripts/serve_agent_openai.py \
  --port 18888 \
  --model <configured-model>

python scripts/materialize_iris_case.py \
  --receipts /path/to/admitted-receipts.jsonl \
  --case-id <case-id> \
  --clean-iris-root /path/to/iris \
  --codeql-dir /path/to/codeql \
  --workspace /path/to/workspace

python scripts/run_native_iris_case.py \
  --workspace /path/to/workspace \
  --run-id <run-id> \
  --bridge-url http://127.0.0.1:18888 \
  --output-dir /path/to/output
```

Use each command's `--help` output for the complete receipt schema and
execution options.

## Evidence Boundary

Database construction is runnability evidence, not a detection result. Native
IRIS path output is evaluated under the baseline protocol and remains distinct
from GCA retrieval, source audit, and runtime confirmation.

## Testing

```bash
python -m pytest -q tests
```
