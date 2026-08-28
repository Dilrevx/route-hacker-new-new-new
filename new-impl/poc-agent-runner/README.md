# PoC Agent Runner

This module launches an autonomous PoC-development session from an audit report
and a fresh independent verification session against the final artifact. It is
separate from `runtime-v2-verifier-redesign`, which prepares and verifies the
runnable application environment.

## Core Files

- `src/gca/poc_agent/runner.py`: prompt construction, agent execution, timeout
  and process-group handling, token accounting, and evidence persistence.
- `src/cli/commands/poc.py`: commands for PoC generation and verification.
- `tests/`: synthetic runner and verifier tests.

## Flow

```text
audit evidence
  -> isolated PoC development session
  -> PoC artifact and reproduction command
  -> fresh verification session
  -> structured verdict and evidence receipt
```

The runner retains prompts, JSONL events, standard error, final messages, token
usage, wall time, command metadata, and artifact paths in the external run
directory. It does not embed case-specific vulnerability rules in the control
plane.

Source checkouts, runtime images, model credentials, PoC artifacts, and
per-finding outputs remain outside Git. Exploit-ready material covered by
coordinated disclosure must not be committed.

## Testing

```bash
PYTHONPATH=src python -m pytest -q tests
```

Tests use a fake agent executable and do not contact a model provider.
