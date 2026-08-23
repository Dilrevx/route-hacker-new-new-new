# Propagated Source-Reviewed Boundary Sidecar

This artifact creates a conservative release-group recall sidecar from propagation-audited source-reviewed boundaries.
It is an ablation input only. It does not update the released guideline catalog, embeddings, rank tables, or paper metrics.

## Summary

- Allowed propagation statuses: ['group_ablation_ready']
- Input boundaries: 33
- Selected boundaries: 1
- Sidecar identities: 8
- Input status counts: {'group_ablation_candidate_outside_fixed_set': 1, 'group_ablation_ready': 1, 'requires_release_regeneration': 31}
- Skip or missing counts: {}

## Policy

- The default mode selects only `group_ablation_ready` boundaries.
- It applies the accepted boundary text to every current release-assigned case for that guideline group.
- Boundaries requiring release regeneration are intentionally skipped until the release catalog is regenerated or reconciled.
- Retrieval claims require a same-identity run against the fixed baseline after this sidecar is consumed.
