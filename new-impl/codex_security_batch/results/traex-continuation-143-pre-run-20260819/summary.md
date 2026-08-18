# Codex Security Native Blind Batch Snapshot

## Scope

- Queue denominator: 143 HCVR v2 cases.
- Current terminal coverage: 103/143 cases.
- Execution policy: native Codex Security full-repository blind audit.
- Dataset vulnerability identifiers and types are joined only after execution for evaluation.

## Aggregate Results

| Metric | Value |
| --- | ---: |
| Accepted | 18 |
| Partial artifacts | 80 |
| Failed after scan attempt | 2 |
| Source preparation failed | 2 |
| Stopped | 1 |
| Pending | 40 |
| Finding candidates | 637 |
| Elapsed scanner seconds | 88993 |

## Models

| Model | Cases |
| --- | ---: |
| `gpt-5.5` | 38 |
| `gpt-5.6-terra` | 62 |

## Coverage

| Coverage | Cases |
| --- | ---: |
| `complete` | 21 |
| `partial` | 78 |
| `unknown` | 3 |

## Finding Severity

| Severity | Candidates |
| --- | ---: |
| `critical` | 24 |
| `high` | 265 |
| `low` | 42 |
| `medium` | 306 |

## Integrity

- Queue SHA256: `65b1daafbf4f806b46ab0779861568d5aa7e7f1c49a3533185ea26e6be82af22`
- Raw records: 112 rows, 102 unique cases.
- Records SHA256: `224a3f4523915d2ca7b2b84864b4498af9536ac561d8d6f0e756cd373e3acdca`
- Manifest still marked `in_progress`: case_051.

## Interpretation Boundary

- Finding counts represent source-backed Codex Security candidates, not runtime-confirmed vulnerabilities.
- `partial_artifacts` preserves usable findings, coverage, and manifest evidence after a non-zero scanner exit.
- The snapshot excludes credentials, authentication state, local source trees, logs, and absolute artifact paths.
