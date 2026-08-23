# Source-Reviewed Sidecar Recall Smoke

This artifact records a smoke evaluation for `guideline-v2-r8-source-reviewed-sidecar-candidate-full-20260823`. It verifies that the source-reviewed sidecar can be consumed by the P3C64 recall runner and produce ranked anchors. It is not a paper-facing recall claim.

## Runs

- `cached3_summary.json`: cases `3`, completed `3`, failed `0`, Hit@200 `1.0000`, elapsed `29.571` seconds.
- `attempt12_summary.json`: cases `12`, completed `3`, failed `9`, Hit@200 `0.2500`, elapsed `168.993` seconds.

`attempt12_summary.json` is environment-contaminated: 9/12 cases failed during GitHub HTTPS clone with `gnutls_handshake() failed`, so it must not be used as a recall metric. The 3 completed cases came from existing cached snapshots and all hit Top-200.

## Same-Identity Smoke Comparison

| identity_key | P3C64 baseline rank | r7 sidecar rank | r8 source-reviewed candidate rank |
| --- | ---: | ---: | ---: |
| `aces__loris::CVE-2026-39985` | NA | NA | 2 |
| `allure-framework__allure2::CVE-2025-52888` | NA | NA | 16 |
| `authguard__authguard::CVE-2021-45890` | 3 | 3 | 1 |

## Interpretation

- The sidecar candidate path is wired correctly: override guidelines were applied, P3C64 embeddings ran, and ranked anchors were emitted.
- The cached 3-case smoke is too small for a recall claim and only overlaps existing full143 rank tables on `authguard__authguard::CVE-2021-45890`.
- Full 48-sidecar or 143-case A/B requires stable source materialization for the missing repositories. The current remote environment failed repeated GitHub HTTPS clones with TLS handshake errors even after retry.
- The next paper-safe gate is a same-identity recall run with fixed identities, snapshots, slicing, P3C64 state, ranking parameters, and Top-K budgets. Use this smoke only as wiring and environment evidence.
