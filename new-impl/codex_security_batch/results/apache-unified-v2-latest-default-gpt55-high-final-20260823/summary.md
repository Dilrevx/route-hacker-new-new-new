# Codex Security Blind Batch Snapshot

## Scope

- Queue denominator: 44 Apache project audits.
- Current terminal coverage: 44/44 queue entries.
- Execution policy: Codex Security harness full-repository blind audit; backend mix: native-codex=10, traex-wrapper=34.
- Queue entries are project-level audit targets; they do not claim one-to-one alignment with a dataset vulnerability.

## Aggregate Results

| Metric | Value |
| --- | ---: |
| Accepted | 10 |
| Partial artifacts | 32 |
| Failed after scan attempt | 1 |
| Source preparation failed | 0 |
| Stopped | 1 |
| Pending | 0 |
| Finding candidates | 187 |
| Elapsed scanner seconds | 171019 |

## Models

| Model | Cases |
| --- | ---: |
| `gpt-5.5` | 44 |

## Coverage

| Coverage | Cases |
| --- | ---: |
| `complete` | 12 |
| `partial` | 30 |
| `unknown` | 2 |

## Finding Severity

| Severity | Candidates |
| --- | ---: |
| `critical` | 4 |
| `high` | 88 |
| `low` | 10 |
| `medium` | 85 |

## Integrity

- Queue SHA256: `b1573fec38a96251858eba1f22cbaa9cabc1a5a4dab926458a5be0ff3387fb97`
- Raw records: 40 rows, 44 cases represented after recovery.
- Recovered from complete core artifacts after interrupted JSONL appends: 4.
- Records SHA256: `518cabd99f9c8eca67edb1e9e803da73d4dbca985f87093a1810b3e1bbc713b4`
- Manifest still marked `in_progress`: none.

## Interpretation Boundary

- Finding counts represent source-backed Codex Security candidates, not runtime-confirmed vulnerabilities.
- `partial_artifacts` preserves usable findings, coverage, and manifest evidence after a non-zero scanner exit.
- The snapshot excludes credentials, authentication state, local source trees, logs, and absolute artifact paths.
