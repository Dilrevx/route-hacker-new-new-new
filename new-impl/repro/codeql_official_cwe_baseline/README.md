# Official CodeQL CWE Baseline

This module evaluates official CodeQL security queries selected by CWE metadata.
It preserves the evaluation denominator and database-availability boundary
without publishing per-case result ledgers.

## Programs

- `scripts/prepare_codeql_cwe_baseline_manifest.py` joins evaluation cases,
  source receipts, database receipts, and public CWE metadata.
- `scripts/build_official_cwe_query_index.py` indexes official security queries
  by their declared CWE tags.
- `scripts/run_codeql_cwe_baseline.py` runs the selected query suites over
  admitted databases.
- `scripts/evaluate_codeql_cwe_baseline.py` evaluates alerts under the fixed
  manifest.
- `scripts/summarize_current_v2_baselines.py` produces aggregate accounting
  across baseline stages.

## Manifest Boundary

The preparation step keeps separate:

- all evaluation entries;
- entries with a verified usable CodeQL database;
- entries whose database could not be admitted.

Missing CWE metadata may be filled from public vulnerability metadata, with the
source recorded in the manifest. Entries that remain unresolved are retained
rather than silently removed.

## Example Shape

```bash
python scripts/prepare_codeql_cwe_baseline_manifest.py \
  --unified-cases /path/to/cases.jsonl \
  --paper-eval-review /path/to/review.jsonl \
  --db-task-jsonl /path/to/database-receipts.jsonl \
  --out-dir /path/to/manifest

python scripts/build_official_cwe_query_index.py \
  --codeql-repo /path/to/codeql-repository \
  --out /path/to/query-index.jsonl \
  --require-security-path

python scripts/run_codeql_cwe_baseline.py \
  --manifest /path/to/usable-manifest.jsonl \
  --query-index /path/to/query-index.jsonl \
  --out-dir /path/to/run \
  --codeql /path/to/codeql
```

Use `--help` for full concurrency, resource, timeout, and resume options.

## Evidence Boundary

A usable CodeQL database proves only that the source was admitted for analysis.
An emitted alert is evaluated separately. Source snapshots, databases, alert
ledgers, and per-case outputs are external runtime artifacts and remain outside
Git.
