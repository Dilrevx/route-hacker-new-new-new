# PoC Agent Runner

This module contains the autonomous PoC-development runner and independent
verifier runner that were used for the 2026-08-17 PoC ground-truth evaluation.

It is intentionally separate from `runtime-v2-verifier-redesign`:

- `runtime-v2-verifier-redesign` builds and verifies runnable application
  environments.
- `poc-agent-runner` launches an AI PoC development session from an audit report,
  then launches a fresh verifier session against the final PoC artifact.

## Core Files

- `src/gca/poc_agent/runner.py`
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

The tests use a fake Agent CLI executable and do not call a real model.
