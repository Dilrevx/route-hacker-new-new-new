# Full-Repository Blind-Audit Baseline

This module contains the queue, execution, summarization, and offline evaluation
utilities for the full-repository blind-audit baseline. It publishes the
implementation contract, not the paper's per-case scan archive.

## Boundary

The scanner receives a pinned source snapshot without CVE identifiers, patches,
known vulnerable files, source/sink labels, or ground-truth anchors. Evaluation
metadata is joined only after scanning.

A scanner finding is a source-backed candidate. It is not automatically a
semantic match to a historical vulnerability and is not a runtime-confirmed
finding.

## Programs

- `build_blind_queue.py` builds and validates the source-only queue.
- `run_blind_batch.sh` launches resumable scans.
- `summarize_blind_batch.py` normalizes terminal attempts and findings.
- `evaluate_gt_anchor_overlap.py` computes post-scan location-overlap
  diagnostics.
- `build_semantic_judge_packets.py` prepares offline semantic-adjudication
  packets.
- `run_semantic_judge.py` runs an optional independent semantic judge.
- `summarize_semantic_judge.py` aggregates judge outcomes.

## Receipt Model

The run directory separates immutable queue entries, per-attempt execution
evidence, normalized findings, and aggregate summaries. Resume logic selects
the latest valid attempt without discarding earlier evidence.

Evaluation distinguishes:

- reported-location overlap;
- LLM-adjudicated semantic agreement;
- source review;
- runtime confirmation.

These are different evidence levels and must not be substituted for one
another.

## Operational Scope

Model credentials, source mirrors, per-case prompts, event streams, raw model
outputs, and result tables are external runtime data and should not be committed.
Use explicit input and output paths when invoking each program; `--help`
documents the accepted schema.

## Minimal Checks

```bash
python build_blind_queue.py --help
python summarize_blind_batch.py --help
python evaluate_gt_anchor_overlap.py --help
python build_semantic_judge_packets.py --help
```
