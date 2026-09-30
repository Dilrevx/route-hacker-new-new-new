# Rank-Quality Stress Multi-Seed Summary

Split seed: `20260722`

Train seeds: `20260722`, `20260723`, `20260724`

## Per-Seed

| train_seed | selected_alpha | raw/raw Hit@100 | raw/raw B@75 | masked/strict Hit@100 | masked/strict B@75 |
| --- | --- | --- | --- | --- | --- |
| 20260722 | 0.7500 | 0.7111 | 131 | 0.5556 | 355 |
| 20260723 | 1.0000 | 0.7333 | 120 | 0.4889 | 337 |
| 20260724 | 0.7500 | 0.7556 | 92 | 0.6444 | 225 |

## Aggregate

| quadrant | MRR mean | MRR std | Hit@100 mean | Hit@100 std | B@75 mean | B@75 std | B@90 mean | B@90 std |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| raw_query_raw_candidates | 0.2774 | 0.0411 | 0.7333 | 0.0222 | 114.3333 | 20.1080 | 769.0000 | 348.1939 |
| raw_query_strict_candidates | 0.1274 | 0.0322 | 0.5778 | 0.0385 | 426.0000 | 128.9922 | 1993.3333 | 689.6349 |
| security_terms_query_raw_candidates | 0.1368 | 0.0295 | 0.6370 | 0.0339 | 202.3333 | 30.5505 | 650.0000 | 419.1575 |
| security_terms_query_strict_candidates | 0.1162 | 0.0086 | 0.5630 | 0.0780 | 305.6667 | 70.4367 | 1630.6667 | 377.1344 |

## Baselines

| method | MRR | Hit@100 | B@75 | B@90 |
| --- | --- | --- | --- | --- |
| bm25_raw | 0.1080 | 0.5111 | 764.0000 | 2501.0000 |
| qwen_raw | 0.2051 | 0.6667 | 153.0000 | 1815.0000 |
