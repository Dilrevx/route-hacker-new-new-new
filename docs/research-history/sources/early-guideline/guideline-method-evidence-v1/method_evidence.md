# Guideline Learned Retriever Evidence v1

## Objective

Learned guideline-conditioned retrieval to reduce full-repository LLM review search space.

This audit treats BM25 as a strong baseline and diagnostic, not as the method.

## Fixed-Split Raw And Strict Evidence

| method | mrr | hit@10 | hit@30 | hit@50 | hit@100 | hit@1000 | budget@75% | budget@90% |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BM25 raw | 0.1080 | 0.2667 | 0.3556 | 0.4444 | 0.5111 | 0.8000 | 764 | 2501 |
| Qwen raw | 0.2051 | 0.3556 | 0.5111 | 0.5333 | 0.6667 | 0.8222 | 153 | 1815 |
| Projection raw | 0.2272 | 0.5111 | 0.6000 | 0.6444 | 0.7111 | 0.9556 | 105 | 389 |
| Projection strict-stress | 0.1491 | 0.2444 | 0.4222 | 0.5556 | 0.5778 | 0.8222 | 518 | 2246 |
| BM25 strict-stress | 0.0692 | 0.1111 | 0.2222 | 0.2889 | 0.4444 | 0.7556 | 922 | 2674 |
| Qwen strict-stress | 0.0972 | 0.1556 | 0.2889 | 0.3556 | 0.4444 | 0.6667 | 1476 | 4227 |

## Strict Projection Multi-Seed Stability

| method | mrr_mean | mrr_std | hit@10_mean | hit@30_mean | hit@50_mean | hit@100_mean | hit@1000_mean | budget@75%_mean | budget@90%_mean |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Projection raw, 3 train seeds | 0.2397 | 0.0097 | 0.4593 | 0.5704 | 0.6222 | 0.7259 | 0.9333 | 108.6667 | 601.3333 |
| Projection strict-stress, 3 train seeds | 0.1108 | 0.0273 | 0.2296 | 0.4000 | 0.4741 | 0.5481 | 0.8222 | 543.6667 | 1916.6667 |

## ViewDropout And Hard-Negative Evidence

ViewDropout:

| method | mrr | hit@10 | hit@30 | hit@50 | hit@100 | hit@1000 | budget@75% | budget@90% |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ViewDropout projection-only raw | 0.2476 | 0.4222 | 0.5778 | 0.6444 | 0.7333 | 0.9333 | 147 | 707 |
| ViewDropout projection-only symbol | 0.1379 | 0.2000 | 0.3333 | 0.4667 | 0.5333 | 0.8444 | 344 | 2425 |
| ViewDropout projection-only strict | 0.1558 | 0.2444 | 0.3111 | 0.4444 | 0.4889 | 0.8000 | 439 | 2767 |

Hard-negative N-view:

| method | mrr | hit@10 | hit@30 | hit@50 | hit@100 | hit@1000 | budget@75% | budget@90% |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Hard-negative N-view selected-alpha raw | 0.1819 | 0.3333 | 0.4667 | 0.5556 | 0.6667 | 0.8667 | 124 | 1262 |
| Hard-negative N-view selected-alpha symbol | 0.0877 | 0.1778 | 0.2444 | 0.3333 | 0.4889 | 0.7556 | 1000 | 2318 |
| Hard-negative N-view selected-alpha strict | 0.0812 | 0.1556 | 0.3778 | 0.4222 | 0.4667 | 0.8000 | 604 | 5289 |
| Hard-negative N-view selected-alpha operation_effect | 0.1784 | 0.3778 | 0.5556 | 0.5556 | 0.7111 | 0.8889 | 302 | 1766 |

## Two-Stage Reranker Evidence

| method | coverage | overall_hit@10 | overall_hit@30 | overall_hit@50 | overall_hit@100 | overall_hit@200 | overall_hit@500 | overall_B@75 | overall_B@90 | conditional_hit@50 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| BM25+Qwen Top200 union reranker | 0.7778 | 0.4667 | 0.5778 | 0.7111 | 0.7111 | 0.7778 | 0.7778 | 140 | n/a | 0.9143 |
| BM25+Qwen Top200 + projection raw/strict Top500 union reranker | 0.9333 | 0.3778 | 0.5556 | 0.6222 | 0.7333 | 0.8000 | 0.9111 | 132 | 493 | 0.6667 |

## Feasibility Judgment

Can continue: `True`

Positive evidence:

- A small trained projection head improves raw retrieval over BM25 and zero-shot Qwen on the fixed held-out split.
- Under strict lexical stress, projection improves over strict BM25 and strict Qwen, so the method is not merely the raw generic embedding baseline.
- Projection lanes add first-stage coverage beyond BM25/Qwen, making a two-stage review-budget architecture plausible.

Negative evidence:

- Strict-stress gains are weaker and less stable than raw gains.
- Naive hard-negative and naive N-view/ViewDropout objectives do not solve long-tail robustness.
- Large multi-lane packets improve coverage but make reranker compression harder.

Next concrete method:

- Promote no-hard raw+strict consistency projection as the first trainable baseline.
- Train the next retriever directly against strict/comment/API/path-masked views instead of only adding more lanes.
- Build a coverage-aware first-stage packet with learned projection lanes, then train a reranker for large noisy packets.
- Report raw and strict metrics together with per-track and p90/p99 failure analysis.
