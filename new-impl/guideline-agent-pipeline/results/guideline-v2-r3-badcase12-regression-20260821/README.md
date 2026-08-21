# Guideline-v2 R3 Bad-Case Regression

This run evaluates the r3 mechanism-guideline sidecar on the same 12 old P3C64 Top-100 misses used by the r1 and r2 checks.

Scope:

- Cohort: 12 old P3C64 Top-100 misses covered by the guideline-v2 sidecar.
- Comparison: old P3C64 query, r1 guideline-v2, r2 guideline-v2, and r3 guideline-v2 on identical case identities.
- Retrieval backend: `p3c64-query-residual` over frozen Qwen3-Embedding-0.6B code vectors.
- Remote full result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-guideline-v2-badcase30-20260821T0505/v2-r3-covered12-linked-gpu6-20260821T180842/`.

Run configuration:

- Commit: `c523840`
- `case_workers`: 1
- `embedding_batch_size`: 32
- `top_k`: 50000
- `guideline_override_count`: 12
- Elapsed: 879.517 seconds

## Result

| Budget | Old P3C64 | r1 guideline-v2 | r2 guideline-v2 | r3 guideline-v2 |
| --- | ---: | ---: | ---: | ---: |
| Top-30 | 0/12 | 1/12 | 0/12 | 1/12 |
| Top-50 | 0/12 | 3/12 | 2/12 | 3/12 |
| Top-100 | 0/12 | 5/12 | 4/12 | 5/12 |
| Top-200 | 2/12 | 6/12 | 7/12 | 7/12 |
| Top-500 | 6/12 | 8/12 | 9/12 | 9/12 |

## Per-Case Notes

- r3 preserves r1's Top-100 recoveries for JEI, PublicCMS, XWiki Commons, XWiki Rendering, and Keycloak.
- r3 keeps the r2 semantic fixes for Apollo, Swagger Codegen CVE-2021-21363, and XWiki Platform, but those remain outside Top-100.
- Keycloak moved from r1 rank 2 to r2 rank 187 when the case was misattributed to webhook SSRF; r3 adds an unsafe URI scheme open-redirect mechanism and recovers it to rank 28.
- Apollo improved from r1 rank 751 to r3 rank 260 after adding request-body resource mismatch authorization, but it still misses Top-200.
- Swagger Codegen CVE-2021-21363 improved from r1 rank 317 to r3 rank 155 after adding temporary directory create-delete-mkdir TOCTOU.
- XWiki Platform improved from r1 rank 5865 to r3 rank 922 after adding privileged server-side capability exposure, but it remains a hard call-context/capability-exposure case.

## Current Decision

r3 is better than r2 and at least as good as r1 at Top-100 on this targeted cohort, while improving Top-200 and Top-500. It is still not a fully satisfactory replacement policy because several ranks remain worse than r1, and the result is from a small sidecar-covered old-miss cohort.

Recommended next action before full 143-case evaluation:

1. Add a regression gate that compares old and new guideline candidates per case on a small held-out set.
2. Consider query fusion between the coarse old guideline and the mechanism-specific guideline, instead of hard replacement.
3. Rerun the full 143-case evaluation only after deciding whether r3 should be used alone or as an old+new fused query.
