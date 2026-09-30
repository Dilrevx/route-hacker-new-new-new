
## Coverage-Aware Packet Builder Smoke

The hard-negative projection lanes increased the lane-union coverage ceiling, but simple RRF did not convert that ceiling into a better final packet. A dev-selected coverage-aware packet builder smoke was added to test whether lane caps can be selected on dev rather than by test inspection.

Script:

- `scripts/build_guideline_coverage_aware_packet.py`

Artifacts:

- Packet output: `.tmp/guideline-coverage-aware-packet-v1/devselected_grid_base3_hnproj2_split20260722/summary.json`
- Dev sweep: `.tmp/guideline-coverage-aware-packet-v1/devselected_grid_base3_hnproj2_split20260722/dev_sweep.jsonl`
- Audit summary: `.tmp/guideline-coverage-aware-packet-v1/coverage_aware_packet_audit_20260722.json`

Sweep setup:

- Selection split: `dev`
- Split seed: `20260722`
- Output budget: `900` candidates per case
- Lanes: BM25 raw, Qwen raw, operation-effect, hard-negative raw projection, hard-negative operation-effect projection
- Cap grid:
  - BM25 raw: `200, 300, 500`
  - Qwen raw: `200, 300, 500`
  - Operation-effect: `200, 300, 500`
  - Hard-negative raw projection: `100, 200, 300, 500`
  - Hard-negative operation-effect projection: `100, 200, 300, 500`
- Sweep size: `432` configurations

Selected caps:

```json
{
  "bm25_raw": 500,
  "qwen_raw": 200,
  "operation_effect": 200,
  "hn_proj_raw": 200,
  "hn_proj_opeffect": 100
}
```

Packet comparison:

| Packet | Selection rule | Dev coverage | Test coverage | Test B@75 | Test B@90 | Test missing cases |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| Dev-selected base RRF cap=300 | dev coverage over base lanes | 33/38 = 0.8684 | 41/45 = 0.9111 | n/a | n/a | `authorization_bypass::23a7e272fa2aabb8`, `concurrent_object_lifecycle::67b4e36c8d7eac30`, `open_redirect::33c0365f8fefcb13`, `authorization_bypass::6714d0c26e3252a0` |
| Hard-negative projection RRF cap=300 | fixed cap with learned lanes | 32/38 = 0.8421 | 41/45 = 0.9111 | n/a | n/a | `business_state_precondition::415b68abb74a13f8`, `concurrent_object_lifecycle::67b4e36c8d7eac30`, `open_redirect::33c0365f8fefcb13`, `authorization_bypass::6714d0c26e3252a0` |
| Coverage-aware dev-selected caps | dev coverage/B@K sweep | 34/38 = 0.8947 | 40/45 = 0.8889 | 68 | 129 | `authorization_bypass::23a7e272fa2aabb8`, `authorization_bypass::6714d0c26e3252a0`, `business_state_precondition::415b68abb74a13f8`, `concurrent_object_lifecycle::67b4e36c8d7eac30`, `open_redirect::33c0365f8fefcb13` |

Interpretation:

- The coverage-aware builder improves dev coverage from `33/38` to `34/38`, so the machinery is capable of selecting a configuration that recovers more dev anchors.
- The same selected configuration drops held-out test coverage from `41/45` to `40/45`. This is a negative generalization result, not a method win.
- The result suggests that a single small dev split is too noisy for direct cap selection. The learned projection lanes are useful, but cap selection needs stronger regularization or a learned calibration objective.
- This also confirms that reranking alone is not the next bottleneck: once a packet covers only `40/45`, no second-stage reranker can exceed that coverage ceiling.

Next method decision:

- Keep the hard-negative projection lane as evidence of complementary learned first-stage signal.
- Do not present the coverage-aware cap sweep as final method improvement.
- Replace direct dev coverage maximization with a more stable packet builder:
  - train a per-candidate calibration score using lane ranks, lane presence, projection scores, and view family;
  - evaluate with group/bootstrap stability on train/dev rather than a single dev coverage objective;
  - keep final selection frozen before test;
  - continue reporting lane-union upper bound, packet coverage, and reranked review-budget metrics separately.
