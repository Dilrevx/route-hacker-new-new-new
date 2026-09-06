# GCA

This repository contains the implementation of the GCA workflow: guideline
distillation, repository-scale candidate retrieval, bounded auditing, and
runtime confirmation.

## Repository layout

- `new-impl/new-guideline/`: guideline generation and candidate retrieval
- `new-impl/guideline-agent-pipeline/`: guideline-conditioned audit drivers
- `new-impl/poc-agent-runner/`: proof-of-concept generation and verification
- `new-impl/compile-builder-v2/`: build and CodeQL repair utilities
- `new-impl/runtime-v2-verifier-redesign/`: runtime task orchestration
- `new-impl/baselines/`: baseline drivers
- `new-impl/new-guideline/guidelines/release-r8/`: released guideline catalog
- `new-impl/hcvr_new_unified_dataset_v2/`: anonymized CVE corpus and fixed
  paper-evaluation allowlist
- `artifacts/p3c64_state.pt`: query-adapter checkpoint
- `artifacts/data_release_manifest.json`: data file sizes and SHA-256 digests

Run commands from the repository root. Each script also provides `--help` for
its complete set of options.

Use Python 3.11 or newer for the packaged components.

## 1. Generate guidelines

```bash
python new-impl/new-guideline/scripts/generate_mechanism_guidelines.py \
  --clusters /path/to/refined_clusters.json \
  --structured /path/to/structured_cves.jsonl \
  --output-dir /path/to/guideline-release
```

## 2. Retrieve repository candidates

```bash
python new-impl/new-guideline/scripts/recall_guideline_anchors.py \
  --qa new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --guideline-file new-impl/new-guideline/guidelines/release-r8/guideline_overrides.jsonl \
  --output-dir /path/to/recall-run \
  --repo-cache /path/to/repo-cache \
  --snapshot-root /path/to/snapshots \
  --embedding-backend p3c64-query-residual \
  --p3c64-state artifacts/p3c64_state.pt \
  --top-k 200
```

## 3. Run bounded audits

```bash
python new-impl/guideline-agent-pipeline/scripts/run_hcvr_case_anchor_audits.py \
  --qa /path/to/qa.json \
  --output-dir /path/to/audit-run \
  --repo-cache /path/to/repo-cache \
  --snapshot-root /path/to/snapshots \
  --codex-home /path/to/codex-home \
  --temp-root /path/to/tmp \
  --limit 20
```

## 4. Run compile repair

```bash
python new-impl/compile-builder-v2/scripts/run_codeql_llm_repair_dispatch.py \
  --failed-receipts /path/to/failed-receipts.jsonl \
  --source-receipts /path/to/source-receipts.jsonl \
  --prior-ledger /path/to/prior-ledger.jsonl \
  --output-dir /path/to/repair-run \
  --dry-run
```

## 5. Run runtime tasks

```bash
export PYTHONPATH="new-impl/runtime-v2-verifier-redesign/src"

python -m gca.runtime_v2 init --run-dir /path/to/runtime-run
python -m gca.runtime_v2 submit-jsonl \
  --run-dir /path/to/runtime-run \
  --input /path/to/tasks.jsonl
python -m gca.runtime_v2 run \
  --run-dir /path/to/runtime-run \
  --workers 4
python -m gca.runtime_v2 status --run-dir /path/to/runtime-run
```

## Tests

The independently packaged components can be tested from their directories:

```bash
(cd new-impl/compile-builder-v2 && python -m pytest -q)
(cd new-impl/runtime-v2-verifier-redesign && python -m pytest -q)
(cd new-impl/poc-agent-runner && PYTHONPATH=src python -m pytest -q)
```
