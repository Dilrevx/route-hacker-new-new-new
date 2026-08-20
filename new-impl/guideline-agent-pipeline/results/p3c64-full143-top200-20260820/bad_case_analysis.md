# P3C64 143-Case Bad-Case Analysis

## Valid Result Boundary

The valid full-set comparison uses the frozen 143-case identity file:

```text
/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-fixed143-20260820T113743/paper_eval_143_identities.jsonl
sha256 e00a8622f2321ea86248de87a2cbbf89b388798e6e6a0d9df6bfbaf69191b805
```

P3C64 completed all 143 cases with no failed rows. The comparable Qwen3-Embedding-4B
baseline uses the same identity set and order.

| Budget | Qwen3-Embedding-4B | P3C64 query-residual | Delta |
| --- | ---: | ---: | ---: |
| Top-30 | 30/143 = 0.2098 | 45/143 = 0.3147 | +15 cases / +10.5 pp |
| Top-50 | 37/143 = 0.2587 | 56/143 = 0.3916 | +19 cases / +13.3 pp |
| Top-100 | 55/143 = 0.3846 | 73/143 = 0.5105 | +18 cases / +12.6 pp |
| Top-150 | 65/143 = 0.4545 | 83/143 = 0.5804 | +18 cases / +12.6 pp |
| Top-200 | 74/143 = 0.5175 | 84/143 = 0.5874 | +10 cases / +7.0 pp |
| Top-300 | 82/143 = 0.5734 | 91/143 = 0.6364 | +9 cases / +6.3 pp |
| Top-500 | 94/143 = 0.6573 | 103/143 = 0.7203 | +9 cases / +6.3 pp |

Use Top-100 or Top-150 for the paper headline if the claim is a percentage-point
gain above 10 pp. Use Top-200 only as `+10 additional recovered cases`, not as
`+10 percentage points`.

## Top-100 Recovery Space

P3C64 currently has 73/143 known-anchor hits at Top-100. There are 70 Top-100
misses. Their first known-anchor ranks are distributed as:

| P3C64 first-hit rank bucket | Case count |
| --- | ---: |
| 101-200 | 11 |
| 201-300 | 7 |
| 301-500 | 12 |
| 501-1000 | 13 |
| 1001-2000 | 12 |
| 2001-5000 | 6 |
| no known-anchor overlap in Top-K output | 5 |

The most realistic next +10 target at Top-100 is the 101-200 bucket. These cases
already have the true anchor close enough that better query specificity or a
light reranker could move them across the cutoff.

## Near-Miss Cases

| Rank | Type | Case | Candidates | Known anchors |
| ---: | --- | --- | ---: | ---: |
| 106 | ssrf | useplunk__plunk::CVE-2026-32096 | 2,105 | 12 |
| 109 | iris | apache__activemq::CVE-2020-11998 | 16,951 | 23 |
| 111 | business_state_precondition | ethyca__fides::CVE-2026-42303 | 18,387 | 12 |
| 115 | authorization_bypass | modelcontextprotocol__python-sdk::CVE-2026-52869 | 1,550 | 11 |
| 128 | business_state_precondition | mezz__justenoughitems::CVE-2024-41565 | 1,251 | 11 |
| 130 | iris | spring-cloud__spring-cloud-gateway::CVE-2022-22947 | 944 | 25 |
| 131 | iris | dspace__dspace::CVE-2025-53621 | 15,450 | 71 |
| 134 | concurrent_object_lifecycle | okta__okta-sdk-java::CVE-2025-66033 | 281 | 23 |
| 142 | business_state_precondition | eclipse__milo::CVE-2022-25897 | 5,687 | 10 |
| 150 | template_expression_injection | xwiki__xwiki-commons::CVE-2024-31996 | 4,878 | 12 |
| 181 | iris | apache__commons-beanutils::CVE-2025-48734 | 1,347 | 20 |

## Regression Space Against Qwen3-Embedding-4B

At Top-100, Qwen3-Embedding-4B recovers 11 cases that P3C64 misses. These are
not proof that fusion should be the main method, but they identify where the
query adapter over-rotated away from useful base-model semantics.

| Qwen4B rank | P3C64 rank | Type | Case |
| ---: | ---: | --- | --- |
| 5 | 128 | business_state_precondition | mezz__justenoughitems::CVE-2024-41565 |
| 17 | 434 | authorization_bypass | openremote__openremote::CVE-2026-49439 |
| 20 | 367 | toctou_check_use_race | parse-community__parse-server::CVE-2026-34363 |
| 20 | 623 | iris | apache__inlong::CVE-2025-27531 |
| 23 | 554 | authorization_bypass | apolloconfig__apollo::CVE-2024-43397 |
| 25 | 248 | template_expression_injection | xwiki__xwiki-rendering::CVE-2025-66474 |
| 30 | 131 | iris | dspace__dspace::CVE-2025-53621 |
| 51 | 1100 | iris | apache__dubbo::CVE-2021-30181 |
| 61 | 181 | iris | apache__commons-beanutils::CVE-2025-48734 |
| 78 | 737 | concurrent_object_lifecycle | api-platform__core::CVE-2026-49858 |
| 80 | 1321 | iris | conductor-oss__conductor::CVE-2025-26074 |

## Main Failure Pattern

The largest Top-100 miss bucket is `iris`: 20 cases. The local dataset has sparse
case descriptions: only 22 of 666 cases include a non-empty
`vulnerability.description`. For many `iris` cases, the current query is a broad
generic security sentence, so retrieval ranks security-looking framework code,
configuration classes, or generic request-handling code ahead of the exact
mechanism anchor.

This points to guideline quality as a real bottleneck. The next method-oriented
improvement should attach mechanism-specific guideline text from the offline
guideline clustering stage, rather than treating `iris` and `m9_wave*` as broad
fallback buckets.

## Implemented Pipeline Hook

`run_hcvr_case_anchor_audits.py` and `recall_guideline_anchors.py` now support a
`--guideline-file` sidecar. The sidecar can be JSONL or JSON, keyed by
`identity_key`, `new_unified_case_id`, or `case_id`, with one of these text
fields:

- `guideline_text`
- `retrieval_guideline`
- `audit_guideline`
- `guideline`

The override is query-side only. It does not modify the dataset, and it does not
read anchors, ranks, file paths, or line numbers. `selected_cases.jsonl` carries
the exact guideline used by retrieval so the downstream audit prompt can reuse
the same text.

## Recommended Next Experiment

Run a guideline-v2 pass over the 70 Top-100 misses:

1. attach mechanism-specific guideline text for `iris`, `m9_wave2`,
   `m9_wave4`, `m9_expansion`, and fallback cases from the offline guideline
   clustering output;
2. rerun P3C64 on the same frozen 143 identity file with `--guideline-file`;
3. compare against the current P3C64 run with `compare_recall_rank_tables.py`;
4. report Top-100/Top-150/Top-200 deltas separately.

Expected upside:

| Lever | Expected Top-100 gain |
| --- | ---: |
| Mechanism-specific guideline overrides | +4 to +8 cases |
| P3C64-v2 anti-regression objective | +3 to +6 cases |
| Candidate/anchor coverage fixes for no-hit rows | +0 to +5 cases |

Direct RRF fusion is not a good primary story. It improves Top-200 to 90/143 but
lowers Top-100 to 70/143, so it is better treated as an upper-bound or
complementarity diagnostic.
