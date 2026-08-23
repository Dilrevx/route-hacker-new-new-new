# Source-Reviewed Release Candidate

This directory is a candidate guideline release generated from accepted source-reviewed boundaries.
It is intended for semantic review and same-identity recall ablation; it is not a final paper metric by itself.

## Summary

- Input boundaries: 33
- Guideline rows: 33
- Release-ready guidelines: 12
- Review-only guidelines: 21
- Case assignments: 48
- Recall sidecar rows: 32
- Unresolved representatives: 5
- Include singleton overrides: False

## Policy

- Input rows come from verifier-valid, judge-accepted source-reviewed boundaries.
- Each boundary becomes an explicit guideline candidate, preserving the old guideline and boundary label for traceability.
- Singleton boundaries stay review-only unless `--include-singleton-overrides` is set.
- No regex fallback, hidden label routing, bad-case answer keys, anchors, ranks, or file-line evidence are used to generate retrieval text.
- Retrieval claims require a same-identity recall run after this sidecar is consumed.
