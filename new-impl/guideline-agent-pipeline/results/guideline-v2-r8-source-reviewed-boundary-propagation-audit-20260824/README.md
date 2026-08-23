# Source-Reviewed Boundary Propagation Audit

This artifact audits how source-reviewed mechanism boundaries can be used in later recall experiments.
It does not modify released guidelines, recall sidecars, rank tables, audit prompts, or training data.

## Summary

- Source-reviewed boundaries: 33
- Guideline groups touched: 18
- Fixed identity input count: 143
- Fixed identity output count: 9
- Minimum representatives for group-level readiness: 2
- Status counts: {'group_ablation_candidate_outside_fixed_set': 1, 'group_ablation_ready': 1, 'requires_release_regeneration': 31}

## Interpretation

- `group_ablation_ready`: the boundary aligns with the current release group and has enough source-reviewed representatives for a same-identity A/B.
- `group_ablation_candidate_low_support`: the boundary aligns with the release group, but the source-reviewed support is currently thin.
- `group_ablation_candidate_outside_fixed_set`: the boundary aligns with the release group, but the supplied fixed identity set cannot measure it.
- `fixed_identity_only`: run a separate fixed sidecar-identity experiment rather than treating it as full release evidence.
- `requires_release_regeneration`: source review produced a refined mechanism that is not yet reflected by the current release group.
- `blocked_by_assignment_conflict`: inspect grouping before using the boundary for recall claims.
- `not_recall_evaluable`: source evidence exists, but the current case/fixed-identity material cannot evaluate it.

## Files

- `boundary_propagation.jsonl`: one row per source-reviewed boundary.
- `group_propagation.jsonl`: guideline-level aggregation.
- `fixed_identity_candidates.jsonl`: optional same-identity subset derived from overlap with the supplied fixed identity file.
- `summary.json`: machine-readable counts and policy.

Paper-facing retrieval claims still require a fresh same-identity recall run after any recall-consumed guideline text changes.
