# GCA

GCA is a guideline-conditioned framework for repository-scale auditing and
runtime confirmation of logic vulnerabilities. This repository is an
implementation snapshot: it contains pipeline and evaluation code, while raw
result archives, source checkouts, model outputs, credentials, and
exploit-ready payloads are kept outside the repository.

## Pipeline

| Stage | Implementation |
| --- | --- |
| Guideline construction and review | `new-impl/new-guideline/` |
| Guideline-conditioned retrieval and bounded audit | `new-impl/guideline-agent-pipeline/` |
| Compile-image repair | `new-impl/compile-builder-v2/` |
| Runtime construction and verification | `new-impl/runtime-v2-verifier-redesign/` |
| PoC execution and independent verification | `new-impl/poc-agent-runner/` |
| Baseline harnesses | `new-impl/codex_security_batch/`, `new-impl/repro/`, and `repro/` |

The online path ranks generic repository views under a fixed review budget,
audits selected locations under a reusable guideline, and carries surviving
hypotheses to executable confirmation. Stages exchange JSON or JSONL receipts
that record source revision, configuration, status, and evidence boundaries.

## Aggregate Results

The paper reports the following aggregate measurements. This source snapshot
does not publish per-case outputs.

| Measurement | Aggregate result |
| --- | --- |
| Retrieval Recall@100 | 0.385 frozen baseline; 0.511 query-adapted |
| Fixed benchmark case hits | 46/143 (32.2%) |
| Production findings with executable runtime evidence | 17 |
| Disclosed findings | 10 |
| Vendor-confirmed findings at submission time | 5 |

These quantities have different evidence boundaries. Retrieval recall measures
whether a known review entry is ranked within a budget; benchmark case hits use
the evaluation protocol defined in the paper; runtime-confirmed and
vendor-confirmed findings are reported separately.

## Release Scope

The implementation snapshot excludes raw per-case prompts, model transcripts,
run logs, cloned repositories, generated images, credentials, host-specific
configuration, and payloads covered by coordinated disclosure. Large result
tables are omitted in favor of the aggregate paper presentation.

Each module README documents its interfaces and tests. External inputs are
supplied through command-line paths and should remain outside Git.

## Testing

```bash
python -m pytest -q new-impl/new-guideline/tests
python -m pytest -q new-impl/guideline-agent-pipeline/tests
python -m pytest -q new-impl/compile-builder-v2/tests
python -m pytest -q new-impl/runtime-v2-verifier-redesign/tests
python -m pytest -q new-impl/poc-agent-runner/tests
```
