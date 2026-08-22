# Codex Security Native Blind Batch Snapshot

## Scope

- Queue denominator: 44 Apache project audits.
- Current terminal coverage: 5/44 queue entries.
- Execution policy: native Codex Security full-repository blind audit.
- Queue entries are project-level audit targets; they do not claim one-to-one alignment with a dataset vulnerability.

## Aggregate Results

| Metric | Value |
| --- | ---: |
| Accepted | 0 |
| Partial artifacts | 4 |
| Failed after scan attempt | 0 |
| Source preparation failed | 0 |
| Stopped | 1 |
| Pending | 39 |
| Finding candidates | 31 |
| Elapsed scanner seconds | 4407 |

## Models

| Model | Cases |
| --- | ---: |
| `gpt-5.5` | 5 |

## Coverage

| Coverage | Cases |
| --- | ---: |
| `partial` | 5 |

## Finding Severity

| Severity | Candidates |
| --- | ---: |
| `high` | 17 |
| `low` | 3 |
| `medium` | 11 |

## Integrity

- Queue SHA256: `b1573fec38a96251858eba1f22cbaa9cabc1a5a4dab926458a5be0ff3387fb97`
- Raw records: 2 rows, 5 cases represented after recovery.
- Recovered from complete core artifacts after interrupted JSONL appends: 3.
- Records SHA256: `e960d8f69539134217010a9c2e3e910413ca0e573d02df6bb897d4086551a569`
- Manifest still marked `in_progress`: none.

## Interpretation Boundary

- Finding counts represent source-backed Codex Security candidates, not runtime-confirmed vulnerabilities.
- `partial_artifacts` preserves usable findings, coverage, and manifest evidence after a non-zero scanner exit.
- The snapshot excludes credentials, authentication state, local source trees, logs, and absolute artifact paths.
