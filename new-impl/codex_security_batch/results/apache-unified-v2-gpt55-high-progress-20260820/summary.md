# Codex Security Native Blind Batch Snapshot

## Scope

- Queue denominator: 44 Apache project audits.
- Current terminal coverage: 23/44 queue entries.
- Execution policy: native Codex Security full-repository blind audit.
- Queue entries are project-level audit targets; they do not claim one-to-one alignment with a dataset vulnerability.

## Aggregate Results

| Metric | Value |
| --- | ---: |
| Accepted | 4 |
| Partial artifacts | 17 |
| Failed after scan attempt | 0 |
| Source preparation failed | 0 |
| Stopped | 2 |
| Pending | 21 |
| Finding candidates | 168 |
| Elapsed scanner seconds | 20418 |

## Models

| Model | Cases |
| --- | ---: |
| `gpt-5.5` | 21 |

## Coverage

| Coverage | Cases |
| --- | ---: |
| `complete` | 5 |
| `partial` | 14 |
| `partial-threat-driven-standard-scan` | 1 |
| `unknown` | 1 |

## Finding Severity

| Severity | Candidates |
| --- | ---: |
| `critical` | 7 |
| `high` | 82 |
| `low` | 8 |
| `medium` | 71 |

## Integrity

- Queue SHA256: `7e22ecdd90ec13fdbe221ee3244ff8cb91e8ea3384c30eb10118a0c4e613b447`
- Raw records: 21 rows, 21 unique cases.
- Records SHA256: `3d8dd6091fc70849c62990d466007c092f863c30307ecd6e1307549b59a65478`
- Manifest still marked `in_progress`: none.

## Interpretation Boundary

- Finding counts represent source-backed Codex Security candidates, not runtime-confirmed vulnerabilities.
- `partial_artifacts` preserves usable findings, coverage, and manifest evidence after a non-zero scanner exit.
- The snapshot excludes credentials, authentication state, local source trees, logs, and absolute artifact paths.
