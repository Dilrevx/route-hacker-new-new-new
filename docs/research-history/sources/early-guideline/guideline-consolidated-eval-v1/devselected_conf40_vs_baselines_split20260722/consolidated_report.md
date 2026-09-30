# Guideline Retrieval Consolidated Evaluation

- split: `test`
- split seed: `20260722`
- dev-selected method: `conf40`

## Main Metrics

| Method | Query stress | Hit@10 | Hit@50 | Hit@100 | Hit@1000 | B@50 | B@75 | B@90 | MRR | p99 rank |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| BM25 | raw | 0.2667 | 0.4444 | 0.5111 | 0.8000 | 90 | 764 | 2501 | 0.1080 | 15426.96 |
| Qwen zero-shot | raw | 0.3556 | 0.5333 | 0.6667 | 0.8222 | 30 | 153 | 1815 | 0.2051 | 2598.24 |
| base | raw | 0.4667 | 0.6444 | 0.7778 | 0.9333 | 14 | 74 | 390 | 0.2678 | 6187.48 |
| base | security_terms | 0.4000 | 0.6222 | 0.7556 | 0.9333 | 17 | 96 | 271 | 0.2246 | 6182.32 |
| latew3 | raw | 0.4667 | 0.6444 | 0.7778 | 0.9556 | 12 | 86 | 564 | 0.2622 | 6281.92 |
| latew3 | security_terms | 0.3778 | 0.5778 | 0.7778 | 0.9333 | 16 | 98 | 301 | 0.2003 | 6909.08 |
| conf40 | raw | 0.5111 | 0.6222 | 0.7778 | 0.9333 | 10 | 87 | 341 | 0.2672 | 6212.56 |
| conf40 | security_terms | 0.4222 | 0.6222 | 0.7556 | 0.9333 | 23 | 90 | 319 | 0.2043 | 5435.76 |
| dev-selected | raw | 0.5111 | 0.6222 | 0.7778 | 0.9333 | 10 | 87 | 341 | 0.2672 | 6212.56 |
| dev-selected | security_terms | 0.4222 | 0.6222 | 0.7556 | 0.9333 | 23 | 90 | 319 | 0.2043 | 5435.76 |

## Top-100 Overlap

- `dev_selected_vs_bm25_top100_raw`: both=20, learned_only=15, baseline_only=3, neither=7
- `dev_selected_vs_bm25_top100_security_terms`: both=21, learned_only=13, baseline_only=2, neither=9
- `dev_selected_vs_qwen_top100_raw`: both=28, learned_only=7, baseline_only=2, neither=8
- `dev_selected_vs_qwen_top100_security_terms`: both=27, learned_only=7, baseline_only=3, neither=8

## Track Counts

- `authentication_session_token_validation`: 3
- `authorization_bypass`: 6
- `business_state_precondition`: 5
- `concurrent_object_lifecycle`: 2
- `file_permission_temp_resource`: 9
- `open_redirect`: 6
- `path_archive_traversal`: 5
- `ssrf`: 5
- `template_expression_injection`: 4
