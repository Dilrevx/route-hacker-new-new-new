# Codex Security Native Blind Batch Snapshot

## Scope

- Queue denominator: 143 HCVR v2 cases.
- Current terminal coverage: 143/143 cases.
- Execution policy: native Codex Security full-repository blind audit.
- Dataset vulnerability identifiers and types are joined only after execution for evaluation.

## Aggregate Results

| Metric | Value |
| --- | ---: |
| Accepted | 32 |
| Partial artifacts | 106 |
| Failed after scan attempt | 2 |
| Source preparation failed | 2 |
| Stopped | 1 |
| Pending | 0 |
| Finding candidates | 737 |
| Elapsed scanner seconds | 152953 |

## Models

| Model | Cases |
| --- | ---: |
| `gpt-5.4` | 40 |
| `gpt-5.5` | 38 |
| `gpt-5.6-terra` | 62 |

## Coverage

| Coverage | Cases |
| --- | ---: |
| `complete` | 44 |
| `partial` | 95 |
| `unknown` | 3 |

## Finding Severity

| Severity | Candidates |
| --- | ---: |
| `critical` | 29 |
| `high` | 326 |
| `low` | 43 |
| `medium` | 339 |

## Integrity

- Queue SHA256: `65b1daafbf4f806b46ab0779861568d5aa7e7f1c49a3533185ea26e6be82af22`
- Raw records: 152 rows, 142 unique cases.
- Records SHA256: `020543c630a0da1b7f04e891418e16551040f6aafbc8a55e7b0d2012322ff50f`
- Manifest still marked `in_progress`: case_051.

## Interpretation Boundary

- Finding counts represent source-backed Codex Security candidates, not runtime-confirmed vulnerabilities.
- `partial_artifacts` preserves usable findings, coverage, and manifest evidence after a non-zero scanner exit.
- The snapshot excludes credentials, authentication state, local source trees, logs, and absolute artifact paths.
