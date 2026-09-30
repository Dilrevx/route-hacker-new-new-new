
## Hard-Negative N-View First-Stage Projection Smoke

To move beyond reranking-only evidence, a hard-negative N-view first-stage projection smoke was added. The goal is to test whether a trainable lane can recover anchors that fixed BM25/Qwen/operation-effect fusion misses, without changing the frozen dataset, candidate pool, anchors, or split.

Script:

- `scripts/run_guideline_hard_negative_nview_projection_smoke.py`

Training setup:

- Frozen split seed: `20260722`
- Train seed: `20260722`
- Views: raw, symbol-masked, strict lexical-stress, operation-effect
- Hard-negative sources: raw BM25, raw Qwen, strict BM25, strict Qwen, operation-effect Top rankings
- Training examples: `7903`
- Hard examples: `7293`
- Random examples: `610`
- Epochs: `2` smoke only
- Selected alpha: `0.75`, selected on dev across all views

Artifacts:

- Trainer output: `.tmp/guideline-hard-negative-nview-projection-v1/raw_symbol_strict_opeffect_hn_smoke2_split20260722_train20260722/summary.json`
- Raw projection Top-900: `.tmp/guideline-hard-negative-nview-projection-v1/raw_hn_smoke2_top900_alpha075_split20260722/top_rankings.jsonl`
- Operation-effect projection Top-900: `.tmp/guideline-hard-negative-nview-projection-v1/operation_effect_hn_smoke2_top900_alpha075_split20260722/top_rankings.jsonl`
- Fusion packet with learned lanes: `.tmp/guideline-fused-toprankings-v1/hn_nview_smoke2_rrf_cap300_out900_bm25_qwen_opeffect_projraw_projop_split20260722/summary.json`

Single-lane export, all `169` cases:

| Lane | Top-900 coverage | B@50 | B@75 | B@90 | Matched-case Hit@100 | Rank p50 | Rank p75 | Rank p90 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Hard-negative projection, raw view | 152/169 = 0.8994 | 4 | 25 | 110 | 0.8816 | 4 | 25.5 | 109.9 |
| Hard-negative projection, operation-effect view | 156/169 = 0.9231 | 5 | 52 | 170 | 0.8333 | 5.5 | 52.75 | 161.5 |

Fixed held-out test split, lane Top-900 anchor coverage:

| Lane set | Covered test anchors | Missing cases |
| --- | ---: | --- |
| Base3: BM25 raw + Qwen raw + operation-effect | 40/45 | `authorization_bypass::23a7e272fa2aabb8`, `authorization_bypass::6714d0c26e3252a0`, `authorization_bypass::a18d121310a55938`, `concurrent_object_lifecycle::67b4e36c8d7eac30`, `open_redirect::33c0365f8fefcb13` |
| Projection2: hard-negative raw + hard-negative operation-effect | 42/45 | `authorization_bypass::6714d0c26e3252a0`, `concurrent_object_lifecycle::67b4e36c8d7eac30`, `ssrf::cc95771a9ceca9b1` |
| Base3 + Projection2 union | 43/45 | `authorization_bypass::6714d0c26e3252a0`, `concurrent_object_lifecycle::67b4e36c8d7eac30` |
| Strict BM25 + strict Qwen | 31/45 | multiple strict-stress misses |

The learned projection lanes recover several anchors absent from the base lanes:

| Recovered case | Learned lane rank |
| --- | ---: |
| `authorization_bypass::23a7e272fa2aabb8` | operation-effect projection rank `206` |
| `authorization_bypass::a18d121310a55938` | raw projection rank `124`, operation-effect projection rank `302` |
| `open_redirect::33c0365f8fefcb13` | raw projection rank `551` |

However, simple RRF fusion with the same `cap=300`, `out900` setting does not convert the larger union into higher final packet coverage:

| Packet | Dev coverage | Test coverage | Test missing cases |
| --- | ---: | ---: | --- |
| Dev-selected base packet | 33/38 = 0.8684 | 41/45 = 0.9111 | `authorization_bypass::23a7e272fa2aabb8`, `concurrent_object_lifecycle::67b4e36c8d7eac30`, `open_redirect::33c0365f8fefcb13`, `authorization_bypass::6714d0c26e3252a0` |
| Hard-negative projection fusion packet | 32/38 = 0.8421 | 41/45 = 0.9111 | `business_state_precondition::415b68abb74a13f8`, `concurrent_object_lifecycle::67b4e36c8d7eac30`, `open_redirect::33c0365f8fefcb13`, `authorization_bypass::6714d0c26e3252a0` |

Interpretation:

- The trainable first-stage lane is feasible and not just a keyword rule: its Top-900 union adds test anchors that the base BM25/Qwen/operation-effect lanes miss.
- The current simple RRF packet builder is the bottleneck. It has access to a `43/45` union across base and learned lanes, but the final `900`-candidate packet still covers only `41/45`.
- The smoke is not yet a paper-level method result. It used only `2` epochs, hard weak negatives, and a fixed RRF packet builder. It validates the technical route but does not complete the stated objective.

Next method decision:

- Do not add more manual keyword rules.
- Do not treat this as a completed learned retriever.
- The next concrete method step should be a coverage-aware packet builder trained or selected on dev. It should decide how many candidates to keep from each lane per case, or learn a first-stage calibration score, with the objective of maximizing dev coverage and B@75/B@90 under a fixed packet budget.
- A subsequent stronger run can increase projection training to `8` epochs, but the immediate bottleneck is packet construction, not whether the projection lane can produce complementary anchors.
