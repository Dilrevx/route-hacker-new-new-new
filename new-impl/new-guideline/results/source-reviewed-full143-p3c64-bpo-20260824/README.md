# Source-Reviewed Guideline Full143 Recall

This run evaluates the source-reviewed release-candidate guideline sidecar on the frozen 143 identity set.

Configuration:

- Backend: P3C64 query-residual over Qwen3-Embedding-0.6B
- Guideline mode: baseline-plus-override
- Sidecar: `results/guideline-v2-r8-source-reviewed-release-candidate-20260824/guideline_overrides.jsonl`
- Identity file: `results/p3c64-fixed143-paper-eval-20260820/paper_eval_143_identities.jsonl`
- Candidate slicing: same runner defaults as previous full143 P3C64 runs
- Top-K retained during this run: 200

## Metrics

| Budget | Old P3C64 | R7 release-ready | Source-reviewed BPO | Delta vs old | Delta vs R7 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Top-30 | 45/143 | 47/143 | 43/143 | -2 | -4 |
| Top-50 | 56/143 | 58/143 | 56/143 | +0 | -2 |
| Top-100 | 73/143 | 76/143 | 75/143 | +2 | -1 |
| Top-150 | 83/143 | 85/143 | 84/143 | +1 | -1 |
| Top-160 | 83/143 | 85/143 | 84/143 | +1 | -1 |
| Top-200 | 84/143 | 87/143 | 85/143 | +1 | -2 |
| Top-300 | 91/143 | 96/143 | 85/143 | -6 | -11 |
| Top-500 | 103/143 | 106/143 | 85/143 | -18 | -21 |
| Top-1000 | 116/143 | 106/143 | 85/143 | -31 | -21 |

MRR: old P3C64 `0.088528`, R7 `0.097064`, source-reviewed BPO `0.087413`.

## Interpretation

This is a valid same-identity full143 run, but it does not show the desired large guideline-only lift. Top-160 is `84/143`, compared with `83/143` for old P3C64 and `85/143` for the broader R7 release-ready sidecar. The current source-reviewed sidecar has 32 explicit override identities, so the full143 ceiling from this artifact is limited unless the source-reviewed guideline coverage is expanded or a reranking/training stage moves existing Top-500 positives into the Top-160 budget.

The failed initial attempt in the same run root used an empty repo cache and hit GitHub TLS clone failures. The committed merged result replaces the one failed `cyberjunky__python-garminconnect::CVE-2026-54447` row with a successful retry from an existing local cache.

## Artifacts

- `recall_results.jsonl`: merged 143-case recall rows
- `selected_cases.jsonl`: selected Top-1 audit anchors
- `summary.json`: merged metrics and timing
- `analysis.json`: all-budget comparison and Top-K crossing details
- `comparison_source_reviewed_vs_old_p3c64_full143.json`: comparison emitted by the existing compare script
- `run_manifest.json`: shard and cache setup
