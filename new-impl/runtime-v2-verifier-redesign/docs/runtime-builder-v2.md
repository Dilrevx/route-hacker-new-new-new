# Runtime Builder v2

Runtime Builder v2 constructs and independently verifies runnable application
environments for pinned source revisions. This document describes the stable
implementation interface; experiment round logs and per-case outcomes are not
part of the source snapshot.

## Design

The subsystem separates five responsibilities:

1. `WorkspaceManager` creates attempt-owned, isolated workspaces.
2. An agent backend prepares a runnable target and submits structured metadata.
3. `RuntimeVerifier` independently launches the declared runtime and evaluates
   HTTP, TCP, command, or log readiness probes.
4. `RuntimeAuditor` checks that the reachable service is the intended
   application rather than a placeholder or incomplete shim.
5. `QueueStore` persists attempts, submissions, evidence, reasons, and final
   state.

Attempts follow a bounded sequence of initial, warm, and clean workspaces.
Rejected metadata or verification evidence is returned as structured feedback
to the next attempt. A task becomes `runtime_ready` only after both mechanical
verification and the independent audit pass.

## Result Contract

A candidate submission identifies:

- launch type and launch command;
- image or Compose metadata where applicable;
- readiness probes with deadlines;
- target revision and workspace ownership;
- cleanup information and evidence paths.

The submission command validates this structure before verification begins.
Accepted metadata is normalized and stored with the attempt receipt.

## Verification Semantics

Readiness is evaluated against a deadline rather than a single probe. HTTP
client responses can establish reachability, while transport failures and
server failures continue retrying until the deadline. Verification relaunches
the candidate independently and retains command output and probe observations.

The auditor may reject a reachable environment when the evidence identifies a
placeholder service, missing application assets, an incorrect target, or another
mismatch with the submitted claim. Rejections require reproducible evidence and
are recorded as retry feedback.

## Queue and Recovery

The SQLite queue records immutable task inputs and append-only attempt history.
The scheduler supports cancellation, retry, review, and adoption of orphaned
attempts. Host-specific caches, credentials, source mirrors, container state,
and run directories remain external to Git.

## Entry Points

- `scripts/runtime_v2.py`: local queue and worker entry point.
- `scripts/runtime_v2_local_ssh_worker.py`: local controller for a remote
  execution worker.
- `scripts/runtime_v2_remote_step.py`: remote attempt step.
- `scripts/runtime_v2_review.py`: review-queue preparation.
- `scripts/runtime_v2_adopt_orphan_attempts.py`: recovery utility.

Inspect the available commands with:

```bash
PYTHONPATH=src python -m gca.runtime_v2 --help
```

## Testing

```bash
python -m pytest -q tests
```

Tests use synthetic runtimes and a fake agent backend. They exercise submission
validation, retry feedback, readiness polling, auditing, queue persistence, and
orchestration without including experiment outputs.
