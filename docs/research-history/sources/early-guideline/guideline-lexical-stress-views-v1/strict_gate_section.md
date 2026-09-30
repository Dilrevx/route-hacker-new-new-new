
## Dev-Selected Method Under Strict Lexical-Stress Gate

This gate tests whether the current clean method is only riding lexical shortcuts. The candidate-side strict stress field removes or masks synthetic headers, comments, identifiers, paths, URLs, string literals, CVE/CWE ids, and related surface vocabulary. BM25 and zero-shot Qwen are rerun on this strict field with persisted Top-900 rankings, then a strict packet is built and reranked with the same four-view method configuration used by the dev-selected raw method.

Artifacts:

- Strict BM25 Top-900: `.tmp/guideline-lexical-stress-views-v1/retrieval_eval_v1_bm25_text_lexical_stress_strict_top900/summary.json`
- Strict Qwen Top-900: `.tmp/guideline-lexical-stress-views-v1/retrieval_eval_v1_qwen_text_lexical_stress_strict_top900/summary.json`
- Strict packet: `.tmp/guideline-fused-toprankings-v1/stress_strict_rrf_cap300_out900_raw_bm25qwen_strict_bm25qwen_opeffect_split20260722/top_rankings.jsonl`
- Strict reranker output: `.tmp/guideline-fusion-aware-reranker-v1/stress_strict_cap300_rawstrict_opeffect_raw_symbol_strict_opeffect_split20260722_train20260722/summary.json`
- Compact comparison artifact: `.tmp/guideline-lexical-stress-views-v1/strict_method_comparison_20260722.json`

Baseline rows below are all-`169` case summaries. Method rows are the frozen held-out test split with all `45` test cases as denominator.

| Setting | Cases | Coverage | Hit@10 | Hit@50 | Hit@100 | Hit@200 | Hit@500 | B@50 | B@75 | B@90 | Rank p50 | Rank p75 | Rank p90 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BM25 raw, all cases | 169 | 169/169 | 0.2071 | 0.4320 | 0.5207 | 0.5917 | 0.7101 | 100 | 1000 | n/a | 90 | 701 | 1897.6 |
| Qwen raw, all cases | 169 | 169/169 | 0.2840 | 0.4970 | 0.6213 | 0.7041 | 0.8047 | 100 | 500 | n/a | 53 | 254 | 1608.8 |
| BM25 strict-stress, all cases | 169 | 169/169 | 0.1006 | 0.2722 | 0.3964 | 0.4793 | 0.6213 | 500 | n/a | n/a | 226 | 1627 | 6098.6 |
| Qwen strict-stress, all cases | 169 | 169/169 | 0.1302 | 0.2959 | 0.3728 | 0.5089 | 0.5976 | 200 | n/a | n/a | 197 | 981 | 2076.8 |
| Dev-selected four-view method, raw packet, test overall | 45 | 41/45 = 0.9111 | 0.6444 | 0.7778 | 0.8222 | 0.9111 | 0.9111 | 4 | 16 | 82 | 4 | 16 | 82 |
| Four-view method, strict packet, test overall | 45 | 37/45 = 0.8222 | 0.4889 | 0.7111 | 0.7778 | 0.8000 | 0.8222 | 7 | 19 | 57 | 7 | 19 | 55.8 |

Interpretation:

- Strict lexical stress materially weakens both lexical and zero-shot embedding baselines. Raw Qwen Hit@100 drops from `0.6213` to `0.3728`; raw BM25 Hit@100 drops from `0.5207` to `0.3964`.
- The current four-view learned method still ranks covered anchors well under the strict packet. On matched test cases, strict reranker Hit@100 is `0.9459`; with the honest all-45 denominator, Hit@100 is `0.7778`.
- The headline loss is mainly first-stage packet coverage: raw packet covers `41/45`, strict packet covers `37/45`. No second-stage reranker can recover anchors absent from the packet.
- This is positive evidence that the method is not just BM25 with more keywords. Under strict stress, the learned multi-view reranker remains far above strict BM25/Qwen at Top-100 on the held-out test denominator.
- This is not yet a complete paper claim. The method still uses raw and operation-effect views heavily: final view weights are approximately raw `0.338`, symbol `0.177`, strict `0.185`, operation-effect `0.300`. The current method is best described as a multi-view calibration/reranking baseline, not a fully lexical-invariant first-stage retriever.

Method implication:

- BM25 should remain a strong baseline and diagnostic, not the contribution.
- The paper method should now move from reranking-only evidence to a trained first-stage retriever or packet builder that improves strict-stress coverage without source-points, traces, anchor edits, or guideline-specific keyword rules.
- The next model objective should optimize full-repo first-stage coverage and long-tail budgets under both raw and strict views. A plausible next step is a guideline-conditioned embedding/projection head trained with raw/strict/operation-effect multi-view consistency and hard lexical distractors sampled from BM25/Qwen top non-anchor packets.
