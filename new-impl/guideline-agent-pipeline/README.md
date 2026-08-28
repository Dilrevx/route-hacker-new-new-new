# Guideline Agent Pipeline

This module implements the bounded-audit portion of GCA and the receipt
interfaces around it. It consumes a frozen guideline-conditioned candidate
queue, performs source-backed audits under a fixed budget, and prepares evidence
for executable confirmation.

Per-case outputs, provider transcripts, credentials, and host-specific run
configuration are intentionally kept outside this implementation snapshot.

## Data Flow

```text
released guideline + ranked repository entries
  -> bounded source audit
  -> structured finding and evidence
  -> PoC handoff packet
```

Repository retrieval is implemented by
`../new-guideline/scripts/recall_guideline_anchors.py`. This module begins
from its saved queue or another queue with the same receipt fields.

## Main Programs

- `scripts/run_hcvr_case_anchor_audits.py` runs source-backed audits for
  selected queue entries.
- `scripts/run_hcvr_backend_b_model_queue.py` evaluates an alternate audit
  backend while holding the queue and budget fixed.
- `scripts/run_hcvr_ablation_a.py` runs controlled ranking, guideline, and
  confirmation-stage ablations with a shared scorer.
- `scripts/extract_poc_handoff_from_audit.py` extracts locations, predicates,
  runtime values, and expected observations for the confirmation stage.
- `scripts/derive_guideline_from_audit.py` sanitizes reviewed audit evidence
  into a candidate reusable guideline.

## Audit Contract

An audit is bound to a selected repository revision, guideline, and candidate
entry. Its output records:

- the audited relation and decision;
- source-backed locations for the missing or incorrect condition;
- the sensitive effect and relevant context;
- runtime preconditions, branch predicates, and observations needed for
  confirmation;
- confidence and execution metadata.

The harness preserves raw evidence in the run directory and writes compact
JSON/JSONL index and summary receipts. A retrieval score remains a routing
signal and is not treated as a vulnerability verdict.

## Example

```bash
python scripts/run_hcvr_case_anchor_audits.py \
  --qa /path/to/qa-receipt.json \
  --output-dir /path/to/audit-output \
  --repo-cache /path/to/repo-cache \
  --snapshot-root /path/to/snapshots \
  --codex-home /path/to/agent-home \
  --temp-root /path/to/temp
```

Build downstream confirmation packets with:

```bash
python scripts/extract_poc_handoff_from_audit.py \
  --audit-index /path/to/audit-output/audit_index.jsonl \
  --output /path/to/poc-handoff.jsonl
```

Model selection, credentials, source snapshots, and result directories are
external runtime inputs. Keep them outside Git.

## Testing

```bash
python -m pytest -q tests
```

The unit tests cover receipt selection, prompt construction, event validation,
guideline derivation, and PoC handoff extraction without publishing paper
results.
