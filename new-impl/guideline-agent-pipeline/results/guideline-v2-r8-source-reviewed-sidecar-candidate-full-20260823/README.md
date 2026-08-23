# Source-Reviewed Guideline Sidecar Candidate

This artifact converts source-reviewed, verifier-valid, judge-accepted `promote_boundary` ledger rows into a review-only recall sidecar candidate.
It is not a paper recall result and it does not modify any released guideline, lexicon entry, embedding, rank table, or audit prompt.

## Summary

- Ledger files: 18
- Ledger rows: 47
- Accepted promotable boundaries: 33
- Sidecar identities: 48
- Unmatched representative cases: 5
- Boundary counts by guideline: {'gl_mech_0001': 1, 'gl_mech_0005': 1, 'gl_mech_0006': 2, 'gl_mech_0007': 1, 'gl_mech_0008': 1, 'gl_mech_0009': 1, 'gl_mech_0011': 1, 'gl_mech_0012': 1, 'gl_mech_0015': 1, 'gl_mech_0022': 1, 'gl_mech_0040': 4, 'gl_mech_0061': 1, 'gl_mech_0116': 2, 'gl_mech_0117': 1, 'review_mech_0017': 3, 'review_mech_0509': 4, 'review_mech_0513': 3, 'review_mech_0514': 4}

## Files

- `guideline_overrides.jsonl`: review-only sidecar keyed by `identity_key` and `case_id` for same-identity recall A/B.
- `boundary_overrides.jsonl`: one row per accepted boundary with the generated recall guideline text.
- `unmatched_representative_cases.jsonl`: representative cases that are source-reviewed but absent from the supplied cases file.
- `summary.json`: manifest and counts.

## Policy

- Rows are included only when the ledger decision is `promote_boundary`, verifier status is valid, and ledger judge decision is `accept`.
- The generated retrieval guideline uses mechanism name, boundary text, missing guard, safe fix semantics, and a same-path confirmation reminder.
- Evidence references, file names, line numbers, CVE IDs, known anchors, ranks, and labels are not inserted into the retrieval text.
- Use this artifact as an explicit ablation input. Any recall claim still requires a same-identity run with fixed identities, source snapshots, candidate slicing, embedding backend, adapter state, ranking parameters, and Top-K budgets.
