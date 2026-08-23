# gl_mech_0001 P3C64 Boundary Recall Smoke Run

This artifact records a focused same-identity recall run for the source-reviewed `gl_mech_0001` boundary: Java temporary directory creation via `File.createTempFile`, delete, then `mkdir`/`mkdirs`.

The run used real P3C64 query-residual embeddings on `bobo5090`; it did not use mock embeddings. Repository materialization initially hit GitHub HTTPS TLS failures, so the same isolated repo-cache was prefilled through SSH and the recall command was rerun unchanged against the same three identities.

## Scope

- Branch/commit: `guideline-v2-mechanism-attribution` / `7fd7db1`
- Case selection: inline identity list, persisted as `.inline_identities.jsonl` in the remote output directory
- Guideline sidecar: `mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/guideline_overrides.jsonl`
- Guideline mode: `baseline-plus-override`
- Embedding backend: `p3c64-query-residual`
- Embedding model: `p3c64-query-residual:/data/lhq/workspace/p3-hard-competition-query-adapter-v1/selection_run_v1/p3c64_state.pt:base=/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B:hidden=128:scale=0.1`
- P3C64 state sha256: `5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16`
- Remote output: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-boundary-recall-r8-gl-mech-0001-20260823/p3c64-recall-gl-mech-0001-3case-20260823-090311`

## Result

- Cases: `3`
- Completed: `3`
- Failed: `0`
- Hit@30: `1.0000`
- Hit@100: `1.0000`
- Hit@200: `1.0000`
- Elapsed seconds: `67.951`

## Per-Case Ranks

- `centic9__jgit-cookbook::CVE-2022-4817`: best known-anchor rank `5`, candidates `108`
- `devent__globalpom-utils::CVE-2018-25068`: best known-anchor rank `1`, candidates `1029`
- `openkm__document-management-system::CVE-2022-3969`: best known-anchor rank `27`, candidates `9649`

## Interpretation

This small run is boundary-level smoke evidence, not a paper-level aggregate claim. It shows that the source-reviewed `gl_mech_0001` semantic boundary is compatible with the current P3C64 recall stack for its three representative same-identity cases. Broader claims still require the full same-identity evaluation set and A/B comparisons.
