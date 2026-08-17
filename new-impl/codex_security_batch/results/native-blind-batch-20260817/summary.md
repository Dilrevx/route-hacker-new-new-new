# Codex Security Native Blind Batch Snapshot

## Scope

- Queue denominator: 143 HCVR v2 cases.
- Current terminal coverage: 63/143 cases.
- Execution policy: native Codex Security full-repository blind audit.
- Dataset vulnerability identifiers and types are joined only after execution for evaluation.

## Aggregate Results

| Metric | Value |
| --- | ---: |
| Accepted | 10 |
| Partial artifacts | 49 |
| Failed after scan attempt | 2 |
| Source preparation failed | 1 |
| Stopped | 1 |
| Pending | 80 |
| Finding candidates | 396 |
| Elapsed scanner seconds | 50367 |

## Models

| Model | Cases |
| --- | ---: |
| `gpt-5.5` | 38 |
| `gpt-5.6-terra` | 23 |

## Coverage

| Coverage | Cases |
| --- | ---: |
| `complete` | 13 |
| `partial` | 47 |
| `unknown` | 2 |

## Finding Severity

| Severity | Candidates |
| --- | ---: |
| `critical` | 13 |
| `high` | 161 |
| `low` | 23 |
| `medium` | 199 |

## Integrity

- Queue SHA256: `65b1daafbf4f806b46ab0779861568d5aa7e7f1c49a3533185ea26e6be82af22`
- Raw records: 72 rows, 62 unique cases.
- Records SHA256: `6f116837baa0d5f325d50eee915869d63d6cfd5b1d6f4d929f0a21ef8a65ecb5`
- Manifest still marked `in_progress`: case_051.

## Interpretation Boundary

- Finding counts represent source-backed Codex Security candidates, not runtime-confirmed vulnerabilities.
- `partial_artifacts` preserves usable findings, coverage, and manifest evidence after a non-zero scanner exit.
- The snapshot excludes credentials, authentication state, local source trees, logs, and absolute artifact paths.
