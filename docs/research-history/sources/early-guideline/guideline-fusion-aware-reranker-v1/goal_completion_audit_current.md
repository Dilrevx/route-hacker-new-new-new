# Goal Completion Audit - Guideline-Conditioned Retrieval

Objective restated:

- Given natural-language security guidelines generated from training-side embedding clusters, retrieve and rank review-worthy relational code locations in frozen repositories that did not participate in guideline construction.
- Keep the task as retrieval / review-space reduction, not vulnerability binary classification.
- Beat BM25 and zero-shot embedding baselines, and evaluate lexical shortcut dependence under candidate-side masking / stress.

Evidence currently available:

- Frozen split seed: 20260722, train/dev/test grouped by project_group.
- Candidate pool: full-repo generic function + sliding_window views.
- Baselines: BM25 and Qwen3-Embedding-0.6B zero-shot.
- Learned methods already evaluated: projection, multi-view projection, seeded fusion, interaction reranker, fusion-aware reranker.
- Current best: fusion-aware reranker over seeded Top-900 packet, test Hit@50=0.7111, Hit@100=0.8222, B@75=66, B@90=276.
- Lexical stress evidence exists for BM25/Qwen/projection.
- Operation-effect standalone lane improves review-budget recall over raw Qwen at Hit@30/50/100/200/500, but simple Top-K fusion does not improve current best packet coverage.

Missing / incomplete:

- Operation-effect is not yet evaluated as a trainable reranker view because all-split operation-effect embeddings are still running.
- The final method is not achieved: first-stage coverage is capped at 41/45 and B@90=276 remains larger than desired.
- Need a comparable overall metrics file for any new reranker run, using all test cases as denominator.

Current next action:

- Complete all-split operation-effect cache/ranking with resume on GPU 3.
- Run fusion-aware reranker with views raw, symbol, strict, operation_effect.
- Compare to current best and update the method report.
