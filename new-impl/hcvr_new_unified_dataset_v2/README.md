# Unified V2 CVE Corpus

This directory contains the public-vulnerability corpus used by the GCA
evaluation. It contains 666 accepted historical cases and 5,451 source-backed
review-entry anchors. The fixed paper-evaluation allowlist contains 143 cases,
one per repository.

## Files

- `dataset/new_unified_cases.v1.jsonl`: case metadata, public repository and
  revision identifiers, vulnerability classification, traces, and embedded
  review-entry anchors.
- `dataset/new_unified_anchors.v1.jsonl`: flattened anchor table.
- `dataset/summary.v1.json`: corpus construction summary.
- `receipts/hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl`: frozen
  143-case paper-evaluation allowlist.
- `receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json`: dataset and anchor
  quality checks for the frozen evaluation set.

The release preserves public CVE/GHSA identifiers, public repository URLs,
checkout revisions, classifications, traces, and anchor locations. Local
filesystem paths, execution commands, local provenance pointers, and embedded
source snippets were removed. Repository snapshots and patch contents are not
redistributed; the evaluation scripts materialize the referenced public
revisions when required.

File sizes and SHA-256 digests are recorded in
`artifacts/data_release_manifest.json` at the repository root.
