# Guideline Coverage Audit

This report audits whether a fixed HCVR identity set is reachable by the offline guideline construction artifacts.
It separates corpus intake, clustering, release gating, and sidecar coverage so recall misses are not misattributed to embedding quality.

## Summary

- Identities: 143
- Primary sidecar: `r8`
- Current primary sidecar coverage: 28/143
- Current candidate upper bound: 53/143
- Current raw/structured upper bound with noise singleton handling: 73/143
- CVE-id upper bound after intake repair: 136/143
- CVE+GHSA upper bound after alias-source repair: 143/143

## Sidecar Coverage

| Sidecar | Covered |
| --- | ---: |
| `propagated` | 1/143 |
| `r5` | 45/143 |
| `r6` | 45/143 |
| `r8` | 28/143 |
| `source_reviewed` | 1/143 |

## Coverage Categories

| Category | Count |
| --- | ---: |
| `missing_from_cve_clustering_raw_structured` | 63 |
| `covered_by_primary_sidecar` | 28 |
| `clustered_but_review_only_release_gate` | 25 |
| `present_in_raw_but_cluster_noise` | 20 |
| `ghsa_or_non_cve_no_cvelist_join` | 7 |

## Inputs

| Input | Path |
| --- | --- |
| `identities` | `new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/paper_eval_143_identities.jsonl` |
| `cases` | `new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl` |
| `raw_cves` | `/tmp/hcvr_guideline_coverage_audit_20260824/raw_cves_combined.jsonl` |
| `structured_cves` | `/tmp/hcvr_guideline_coverage_audit_20260824/structured_cves_combined.jsonl` |
| `clusters` | `/tmp/hcvr_guideline_coverage_audit_20260824/refined_clusters_combined.json` |
| `mechanism_candidates` | `new-impl/new-guideline/results/mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/mechanism_candidates.jsonl` |
| `review_queue` | `new-impl/new-guideline/results/mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/review_queue.jsonl` |
| `sidecars.propagated` | `new-impl/new-guideline/results/guideline-v2-r8-propagated-boundary-sidecar-ready-only-20260824/guideline_overrides.jsonl` |
| `sidecars.r5` | `new-impl/new-guideline/results/mechanism-guideline-preview-v2-cluster-scope-r5-combined-baseline-20260823/guideline_overrides.jsonl` |
| `sidecars.r6` | `new-impl/new-guideline/results/mechanism-guideline-preview-v2-cluster-scope-r6-candidate-20260823/guideline_overrides.jsonl` |
| `sidecars.r8` | `new-impl/new-guideline/results/mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/guideline_overrides.jsonl` |
| `sidecars.source_reviewed` | `new-impl/new-guideline/results/guideline-v2-r8-source-reviewed-release-candidate-20260824/guideline_overrides.jsonl` |

## Interpretation

- `missing_from_cve_clustering_raw_structured` means the case never entered the offline CVE clustering corpus.
- `present_in_raw_but_cluster_noise` means the case entered raw/structured CVE data but HDBSCAN did not assign it to a cluster.
- `clustered_but_review_only_release_gate` means the case has a candidate guideline but release policy kept it out of the recall sidecar.
- `ghsa_or_non_cve_no_cvelist_join` means the current CVEList-oriented join cannot connect the advisory identity.
