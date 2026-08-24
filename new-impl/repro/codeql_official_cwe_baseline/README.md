# Official CodeQL CWE Baseline

This baseline evaluates the official CodeQL queries whose metadata tags match a
case's CWE. It is intended for comparison against IRIS, Codex Security, and GCA
on the same HCVR unified-v2 case denominator.

The scripts keep the denominator explicit:

- `current_143_manifest.jsonl`: every current paper-eval case from the unified-v2
  receipt;
- `current_143_with_usable_codeql_db_manifest.jsonl`: current paper-eval cases
  that also have an existing usable CodeQL database;
- `current_143_missing_codeql_db_manifest.jsonl`: current paper-eval cases whose
  database still needs to be built or repaired.

The current dataset snapshot may have incomplete CWE fields. `prepare` therefore
uses dataset CWE labels first and fills missing labels through public OSV/NVD
metadata, recording the source in each row. Cases that still have no CWE stay in
the manifest as `cwe_source=missing`.

## Example Run

```bash
ROOT=/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq
REPO=$ROOT/route-hacker-new-new
DBRUN=$ROOT/codeql-db-runs/new-unified-143-v1
OUT=$ROOT/codeql-baselines/official-cwe-current143-$(date +%Y%m%d-%H%M%S)
CODEQL=$ROOT/repro/iris/codeql/codeql
QLREPO=$ROOT/hcvr/toolchains/github-codeql-main-shallow

python3 $REPO/new-impl/repro/codeql_official_cwe_baseline/scripts/prepare_codeql_cwe_baseline_manifest.py \
  --unified-cases $REPO/new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --paper-eval-review $REPO/new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl \
  --db-task-jsonl $DBRUN/tasks.v1.jsonl \
  --db-task-jsonl $DBRUN/tasks-materialized.v1.jsonl \
  --out-dir $OUT/manifest \
  --skip-nvd

python3 $REPO/new-impl/repro/codeql_official_cwe_baseline/scripts/build_official_cwe_query_index.py \
  --codeql-repo $QLREPO \
  --out $OUT/query_index/official_cwe_queries.jsonl \
  --require-security-path

python3 $REPO/new-impl/repro/codeql_official_cwe_baseline/scripts/run_codeql_cwe_baseline.py \
  --manifest $OUT/manifest/current_143_with_usable_codeql_db_manifest.jsonl \
  --query-index $OUT/query_index/official_cwe_queries.jsonl \
  --out-dir $OUT/run \
  --codeql $CODEQL \
  --max-workers 2 \
  --threads 2 \
  --ram 12000 \
  --timeout-seconds 1800 \
  --resume

python3 $REPO/new-impl/repro/codeql_official_cwe_baseline/scripts/evaluate_codeql_cwe_baseline.py \
  --manifest $OUT/manifest/current_143_with_usable_codeql_db_manifest.jsonl \
  --run-ledger $OUT/run/run_ledger.jsonl \
  --out-dir $OUT/eval

python3 $REPO/new-impl/repro/iris_native_traex/scripts/prepare_current_v2_iris_queue.py \
  --current-review $REPO/new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl \
  --codeql-manifest $OUT/manifest/current_143_with_usable_codeql_db_manifest.jsonl \
  --strict-admission /path/strict-admission.jsonl \
  --iris213-case-status $REPO/new-impl/repro/iris_native_traex/results/iris213-cwebenchjava-status-20260824/iris213_case_status.csv \
  --out-dir $OUT/iris_current_v2_queue

python3 $REPO/new-impl/repro/codeql_official_cwe_baseline/scripts/summarize_current_v2_baselines.py \
  --current-review $REPO/new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl \
  --codeql-manifest $OUT/manifest/current_143_with_usable_codeql_db_manifest.jsonl \
  --codeql-eval-summary $OUT/eval/evaluation_summary.json \
  --iris-current-queue-summary $OUT/iris_current_v2_queue/current_v2_native_iris_queue_summary.json \
  --iris-current-case-status $OUT/iris_current_v2_queue/current_v2_native_iris_case_status.jsonl \
  --out-dir $OUT/report
```

The primary paper table should use `eval/evaluation_summary.json`. The CSV files
retain per-case and per-alert details for audit.
