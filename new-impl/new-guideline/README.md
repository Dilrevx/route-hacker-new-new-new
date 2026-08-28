# Guideline Construction and Retrieval

This module contains the offline guideline-release utilities, generic
repository-view retrieval, guideline review tools, and audit experiment
harnesses used by GCA. It is documented as implementation code; per-case result
archives and model transcripts are intentionally not included.

## Components

### Guideline release

- `scripts/generate_mechanism_guidelines.py` converts structured root-cause
  records and refined clusters into reviewable mechanism-level guidelines.
- `guidelines/mechanism_lexicon.seed.json` defines reusable mechanism
  vocabulary and evidence roles.
- `guidelines/guideline_review_ledger.template.jsonl` records reviewer
  decisions and provenance.
- The `build_*`, `verify_*`, and `evaluate_guideline_groups.py` utilities
  prepare review packets, validate ledgers, and build versioned release
  sidecars.

The generator consumes prepared JSON/JSONL artifacts and writes guideline text,
an index, provenance, review queues, and optional identity-keyed sidecars.

```bash
python scripts/generate_mechanism_guidelines.py \
  --clusters /path/to/refined_clusters.json \
  --structured /path/to/structured_cves.jsonl \
  --output-dir /path/to/guideline-release
```

### Guideline-conditioned retrieval

`scripts/recall_guideline_anchors.py` materializes a pinned source snapshot,
creates generic sliding-window views, embeds the guideline and candidate pool,
ranks the complete pool, and writes a bounded Top-K queue. Known anchors are
used only by optional post-run evaluation.

Supported embedding paths are:

- an OpenAI-compatible embedding endpoint;
- a local SentenceTransformers model;
- a query-only residual adapter loaded from an externally supplied state file.

```bash
python scripts/recall_guideline_anchors.py \
  --qa /path/to/qa-receipt.json \
  --cases-file /path/to/cases.jsonl \
  --repo-cache /path/to/repo-cache \
  --snapshot-root /path/to/snapshots \
  --output-dir /path/to/recall-output \
  --embedding-backend openai \
  --embedding-base-url http://127.0.0.1:8001/v1 \
  --embedding-model /path/or/model-id \
  --top-k 100
```

For query-residual inference, additionally select
`--embedding-backend p3c64-query-residual` and pass `--p3c64-state`.
Model files and checkpoints are not committed to this source snapshot.

### Bounded audit

- `scripts/run_hcvr_case_anchor_audits.py` materializes selected revisions and
  launches source-backed audits.
- `scripts/run_hcvr_backend_b_model_queue.py` runs a fixed queue with a
  selectable audit backend.
- `scripts/run_hcvr_ablation_a.py` applies controlled stage ablations under a
  shared scorer.
- `scripts/extract_poc_handoff_from_audit.py` converts audit evidence into
  downstream PoC packets.
- `scripts/derive_guideline_from_audit.py` creates a sanitized candidate
  guideline from reviewed audit evidence.

Run outputs should be written outside the repository. They contain
machine-specific paths and may contain security-sensitive evidence.

## Review Utilities

The remaining scripts provide deterministic transformations for guideline
quality review, evidence coverage, sidecar comparison, recall diagnostics, and
revision backlog construction. They do not silently change a released
guideline: promotion requires an explicit reviewed ledger or release-building
step.

## Evidence Boundaries

- Retrieval scores rank review entries; they are not vulnerability verdicts.
- Dataset anchors are evaluation labels, not ranking inputs.
- LLM judge output is advisory review evidence.
- Runtime confirmation and vendor adjudication are distinct evidence levels.
- Detailed case identities, prompts, and outputs are excluded from this
  implementation snapshot.

## Testing

```bash
python -m pytest -q tests
```

Tests use local fixtures and do not require access to the paper's result
archive.
