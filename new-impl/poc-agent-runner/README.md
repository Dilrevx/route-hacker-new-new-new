# PoC Agent Runner

This module contains the autonomous PoC-development runner and independent
verifier runner that were used for the 2026-08-17 PoC ground-truth evaluation.

It is intentionally separate from `runtime-v2-verifier-redesign`:

- `runtime-v2-verifier-redesign` builds and verifies runnable application
  environments.
- `poc-agent-runner` launches an AI PoC development session from an audit report,
  then launches a fresh verifier session against the final PoC artifact.

## Main Use Cases

The PoC agent has two primary workflows:

1. **Historical CVE reproduction evaluation.** Given a known CVE, pinned source
   revision, and runtime artifact, the agent measures whether the pipeline can
   reproduce the historical vulnerability and produce a faithful executable
   proof. This workflow may target old or intentionally vulnerable revisions.
2. **New-project false-positive audit.** Given new Codex Security candidates on
   a project's current branch, the agent checks whether the candidate is a real
   present-day issue worth further human review or vendor reporting.

For the new-project false-positive audit workflow, only run PoC validation when
the target repository's default branch has a latest commit dated in 2026. If the
latest `master` or default-branch commit is older than 2026, skip the candidate
as low-priority legacy surface instead of spending PoC-agent budget on it. This
gate does not apply to historical CVE reproduction evaluation, where old
revisions are expected by design.

## Core Files

- `src/route_hacker/poc_agent/runner.py`
  - `run_poc_agent`
  - `run_poc_verifier`
  - prompt builders, token accounting, timeout/process-group handling, and run
    evidence persistence.
- `src/cli/commands/poc.py`
  - Typer commands for `poc run` and `poc verify`.
- `docs/poc-agent-technical-architecture-plan.md`
  - Living architecture record for the PoC subsystem.

## Expected Flow

```text
audit report
  -> poc run
  -> PoC artifact + reproduction command
  -> poc verify
  -> CONFIRMED / REJECTED / INVALID_POC / BLOCKED / INCONCLUSIVE
```

The runner records prompts, JSONL event streams, stderr, final messages, token
usage, wall time, and command metadata. It does not hard-code vulnerability
semantics or mechanically decide whether a vulnerability exists.

## Test

```bash
PYTHONPATH=src python3 -m pytest -q tests
```

The tests use a fake TraeX executable and do not call a real model.
