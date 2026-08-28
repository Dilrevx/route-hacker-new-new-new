# VulRAG Function-Level Baseline Harness

This module runs a function-level VulRAG baseline while preserving VulRAG's
knowledge corpus, three-way BM25 retrieval, and detection path. The model
transport is provided by a configurable local agent command.

The module publishes implementation code only. Evaluation identities, extracted
functions, prompts, raw responses, and per-case result ledgers remain external.

## Programs

- `build_function_packets.py` extracts a syntax-tree function from each
  admitted source receipt and builds a neutral runtime packet.
- `run_vulrag_agent_batch.py` executes resumable function-level detection.
- `summarize_results.py` aggregates terminal accounting.
- `compare_results.py` compares aggregate runs produced under the same
  denominator and packet set.

## Input Boundary

The packet builder uses source receipts to locate a real function in a pinned
revision. Runtime packets exclude vulnerability labels, patches, fix revisions,
known findings, and ground-truth locations as model instructions.

Supported grammars are C#, Go, Java, JavaScript, PHP, Python, Ruby, TypeScript,
and TSX. Inputs that cannot be represented as a syntax-tree function are marked
unresolved rather than converted into synthetic windows.

## Example Shape

```bash
python build_function_packets.py \
  --cases /path/to/cases.jsonl \
  --output-dir /path/to/function-packets

python run_vulrag_agent_batch.py \
  --packets /path/to/function-packets \
  --output-dir /path/to/run \
  --model <configured-model>

python summarize_results.py \
  --run-dir /path/to/run \
  --output /path/to/aggregate-summary.json
```

Use each program's `--help` output for the exact input fields and execution
options.

## Interpretation

This is a function-level baseline, whereas GCA ranks complete repositories
before auditing selected entries. Detection rate is reported over successfully
materialized function packets and must retain the unresolved-input denominator.
Model substitutions are baseline variants, not official VulRAG results.
