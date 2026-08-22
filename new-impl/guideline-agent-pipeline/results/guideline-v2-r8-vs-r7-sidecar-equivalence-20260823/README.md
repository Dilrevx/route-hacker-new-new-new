# Guideline Sidecar Equivalence

This report compares guideline sidecars by the key and guideline text that the recall runner consumes.
It intentionally ignores release-only metadata that does not affect `apply_guideline_overrides()`.

## Summary

- Left: `guideline-v2-r7-evidence-gated-sidecar`
- Right: `guideline-v2-r8-release-ready-sidecar`
- Left rows: 189
- Right rows: 189
- Common rows: 189
- Same key set: True
- Changed consumed guideline texts: 0
- Recall-consumed text equivalent: True

## Boundary

If `recall_consumed_text_equivalent` is true, a deterministic recall runner with the same identity file, snapshots, candidate slicing, embedding backend, and ranking parameters should produce the same rankings even if the sidecar files differ in non-consumed metadata.
This equivalence report is evidence for reusing an existing same-identity recall table only under those unchanged runtime conditions.
