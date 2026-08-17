# Runtime Builder v2

Runtime Builder v2 is an autonomous Agent queue for constructing runnable
application environments from natural-language vulnerability tasks. It does not
use the v1 fleet queue, build controller, admission checks, or artifact gates.

## Round Update Record

### Round 0: Unified 143 baseline

- Goal: Complete the original unified runtime-v2 queue and classify terminal outcomes.
- Scope: 143 vulnerability runtime tasks.
- Action: Ran the original builder, post-Agent verifier, and retry sequence.
- Output: 25 `runtime_ready`, 118 `failed`.
- Verification: All tasks reached a terminal state and SQLite `quick_check` passed.
- Decision: Many failures mixed runtime defects with late metadata/probe protocol errors.
- Next Round: Move metadata feedback into the active Builder Agent attempt.

### Round 1: Submission and self-repair

- Goal: Let the Builder Agent repair malformed metadata before its attempt ends.
- Scope: Result contract, SQLite persistence, prompt, and CLI.
- Action: Added `submit-result`, attempt-scoped submission history, structured reasons,
  accepted-result normalization, and synchronous rejection output.
- Output: An attempt may submit repeatedly until one candidate is accepted.
- Verification: Unit tests cover rejected-then-accepted submissions and old database migration.
- Decision: Only an accepted database submission may enter runtime verification.
- Next Round: Add independent mechanical verification and AI claim audit.

### Round 2: Mechanical verification and AI audit

- Goal: Verify that a mechanically reachable service supports the declared runtime-ready claim.
- Scope: Local orchestrator and local-to-remote SSH workers.
- Action: Split metadata submission, clean mechanical launch/probes, and evidence-backed
  TraeX/Codex audit. Added structured reasons and audit artifacts.
- Output: Final task status remains binary: `runtime_ready` or `failed`.
- Verification: Focused suite passes for submission, audit, orchestration, and persistence.
- Decision: AI audit may reject only with reproduction commands, observations, and persisted
  evidence. Invalid or unavailable audit output is an infrastructure failure.
- Next Round: Re-review representative cases from the original 143 run, then run the full review.

### Round 3: Representative smoke and verifier hardening

- Goal: Exercise the redesigned protocol on old pass/fail cases before a full 143-task review.
- Scope: Five cases covering Java image, Java Compose, PHP Compose, and prior timeout paths.
- Action: Prepared a read-only review queue, ran two SSH workers, and retained the first smoke
  as defect evidence after an immediate HTTP connection reset was classified as terminal.
- Output: HTTP, TCP, command, and log probe timeouts now represent total readiness deadlines
  with polling. HTTP 4xx proves reachability; HTTP 5xx and transport errors retry until the
  deadline. Builder prompts now require an attempt-derived `docker compose -p` project name.
- Verification: The previously failed Klaw artifact passed after 13 HTTP attempts in 12.348
  seconds. The focused and full local suites pass, including readiness polling, HTTP 404
  reachability, remote audit evidence existence, and Compose project isolation.
- Decision: An immediate connection refusal or reset during startup is not a runtime failure.
  Builder self-tests and the verifier must use the same attempt-owned Compose namespace.
- Next Round: Complete a fresh five-case smoke with independent audit enabled.

### Round 4: Fresh five-case review

- Goal: Confirm that metadata self-repair, independent relaunch, and AI audit produce defensible
  binary outcomes on representative old results.
- Scope: Loris, Klaw, InLong, Chamilo, and Jenkins Advisor Plugin from the immutable unified run.
- Action: Rebuilt each case in a new review run while preserving the old run read-only. The
  auditor rejected Loris's first synthetic Node service with `not_main_application_runtime`,
  returned that reason to the next retry, and rejected Chamilo's first reachable backend with
  `main_application_frontend_assets_empty` because its required JS and CSS files were one byte.
  Both reasons were persisted and supplied to the following Builder attempt.
- Output: All five cases are `runtime_ready`: four old `failed` results changed to
  `runtime_ready`, and one old `runtime_ready` result remained `runtime_ready`. Loris passed on
  its clean third attempt; Chamilo passed on its warm second attempt after producing 1,368 real
  Webpack assets.
- Verification: Klaw serves the real login application after independent relaunch. InLong serves
  the Manager Swagger/API endpoint from the exact vulnerable checkout with MySQL healthy and
  zero Manager restarts. Jenkins starts a real Jenkins 2.479.3 runtime containing the vulnerable
  plugin revision. Loris serves the PHP/Apache/MariaDB application. Chamilo returns HTTP 200 for
  `/login`, serves all 11 referenced critical bundles, and passes an attempt-local asset
  integrity probe. Every successful candidate passed both mechanical verification and the
  independent audit. The source run queue hash remained
  `a66549263013f4c93af3d98825aec419693a5b3a7ab99ae8360728aeeba8116f`.
- Decision: Passing probes are necessary but not sufficient. The auditor may veto reachable
  shims or incomplete applications and must persist reproducible evidence; a valid veto becomes
  retry feedback. A failed attempt is not the same as a failed task.
- Next Round: Prepare and start the full 143-task immutable review because the fresh smoke found
  no remaining shared protocol defect.

### Round 5: Full immutable 143-task review

- Goal: Re-review every old terminal result under the redesigned submission, verification, and
  audit protocol without rewriting the authoritative baseline.
- Scope: All 143 tasks from
  `runtime-v2-unified-143-20260813T203628Z`, including the old 25 `runtime_ready` and 118
  `failed` results.
- Action: Created a separate 143-task review queue at
  `runtime-v2-review-full143-20260815T120149Z`, preserved the source queue hash before and after
  preparation, and started two local Builder/auditor workers against the remote runtime host.
  The workers run in the local tmux session `runtime-v2-full143-20260815`.
- Output: The review queue contains 143 tasks. At launch, two tasks are `running` and 141 are
  `queued`; no full-run outcome is claimed yet.
- Verification: The new manifest and queue each contain 143 tasks. The source queue SHA-256
  remains `a66549263013f4c93af3d98825aec419693a5b3a7ab99ae8360728aeeba8116f`.
  Worker concurrency is fixed at two, and all attempt workspaces and evidence are written under
  the new review run.
- Decision: Treat the old 118 `failed` records as historical outcomes requiring re-review, not
  as 118 confirmed runtime defects. Publish transition counts only after the new queue reaches
  terminal states.
- Next Round: Monitor the queue, classify persistent failure reasons by stage and code, generate
  `review-report.json` and `review-report.md`, and update this record with final transitions.

### Round 6: `/mnt` runtime storage migration

- Goal: Keep host storage pressure from being classified as an application runtime failure while
  allowing the immutable 143-task review to continue.
- Scope: Remote Agent shell state, build caches, verifier error classification, and successful
  runtime resource lifecycle.
- Action: Paused only unclaimed queue entries, moved `.claude` and `.gradle` state to the
  run-specific `/mnt` host-runtime directory with compatibility symlinks, and added a mandatory
  remote environment for temporary files and Maven, Gradle, npm, Yarn, pip, Go, Composer, and
  Docker client caches. Added explicit ENOSPC/EDQUOT detection and attempt-scoped cleanup after a
  successful audit.
- Output: Fresh SSH sessions and common build tools write through `/mnt`; final public states
  remain `runtime_ready` or `failed`, while storage exhaustion is persisted as
  `infrastructure/storage_exhausted`. The maintenance window ended with Filament accepted as the
  67th `runtime_ready` task. All 76 paused tasks were restored to `queued` in one transaction, and
  the resumed two-worker queue immediately claimed tasks 68 and 69.
- Verification: The local focused suite passes 9 tests and the full suite passes 22 tests. The
  synchronized remote implementation matches the local SHA-256 hashes. Fresh SSH login no longer
  emits shell-hook ENOSPC errors, and `/data` user-visible free space recovered from zero to about
  10 GB without global Docker pruning. The pre-resume queue backup is
  `maintenance/queue-before-storage-resume-20260815T202936Z.db` with SHA-256
  `47defe133ab358e115aa3795763142a72dc1644dbd88049837787dc91dfa346a`. The resumed worker command
  includes the explicit run-specific `/mnt` runtime root, and both newly claimed Builder Agents
  issue SSH commands with `/mnt` values for temporary files and all configured build caches.
- Decision: Preserve Docker images and all attempt evidence, but stop attempt-owned runtime
  instances after audit. Do not publish host storage exhaustion as a runtime defect. A worker
  bootstrap failure before task claim, such as the observed missing local `PYTHONPATH=src`, is an
  orchestration error and is corrected without changing task state.
- Next Round: Continue the remaining 76-task review at concurrency two, monitor
  `infrastructure/storage_exhausted` separately from runtime failures, and publish transition
  counts only after the queue reaches terminal states.

### Round 7: Post-migration queue continuity

- Goal: Confirm that the resumed review preserves concurrency, accepts valid runtimes, and does
  not convert host-storage warnings into runtime failures.
- Scope: Attempts 79 through 82, queue transitions after each completed audit, worker process
  children, and all persisted storage or auditor-infrastructure events.
- Action: Polled attempts 79 and 80 through terminal status, checked that each released worker
  slot immediately claimed the next queued task, inspected the live SSH child environment, and
  searched persisted event details for storage exhaustion and auditor infrastructure failures.
- Output: Handlebars attempt 79 and Horilla CRM attempt 80 both passed mechanical verification
  and independent audit. The queue advanced to 74 `runtime_ready`, 2 `running`, and 67 `queued`;
  attempts 81 and 82 started for Horilla HR and oh-my-posh.
- Verification: The local worker remains alive with two active Builder children. Its remote
  commands export the run-specific `/mnt` temporary and package-cache paths. There are no
  `storage_exhausted` attempts or `audit_infrastructure_failed` events. The only persisted
  `No space left on device` text is shell-hook stderr attached to old attempt 63; that command
  returned successfully, all mechanical probes passed, and the task reached `runtime_ready`.
  `/data` has about 5.1 GB available despite displaying 100% usage, while `/mnt` has about
  1.1 TB available.
- Decision: Continue at concurrency two. Treat shell-hook stderr as diagnostic evidence rather
  than a runtime defect when the invoked command and probes succeed; classify actual ENOSPC or
  EDQUOT launch/probe failures as infrastructure.
- Next Round: Let attempts 81 and 82 reach audit, continue claiming the remaining queue, and
  stop only for a reproducible infrastructure/storage failure or a shared verifier defect.

### Round 8: Full 143 review completion

- Goal: Close the immutable 143-task review with a final transition report and verify that all
  public task states are terminal.
- Scope: The full `runtime-v2-review-full143-20260815T120149Z` queue, final attempt records,
  generated review report, worker lifecycle, and host storage state at completion.
- Action: Polled the queue after worker exit, checked active attempt counts, listed intermediate
  failed attempts with their final task states, and generated `review-report.json` plus
  `review-report.md` from the preserved source manifest.
- Output: All 143 review tasks are `runtime_ready`. The transition report records 118 old
  `failed` tasks changed to `runtime_ready`, and 25 old `runtime_ready` tasks remained
  `runtime_ready`. There are no final failure reason stages or codes.
- Verification: The queue has zero non-ready tasks and zero active attempts. The worker process
  exited after draining the queue. The nine `failed` attempt records are intermediate attempts;
  every corresponding task later reached `runtime_ready`. The final report has
  `terminal_count: 143` and `task_count: 143`.
- Decision: The old unified baseline's 118 failures should be treated as verifier/protocol-era
  outcomes, not as confirmed inability to build runtimes under the redesigned protocol. The
  redesigned review established a binary public result of 143/143 `runtime_ready`; intermediate
  attempt failures remain useful retry evidence but do not count as final task failures.
- Next Round: Audit a sample of final artifacts for quality beyond readiness, summarize the
  nine intermediate retry causes, and address host `/data` exhaustion separately from runtime
  readiness because `/data` reached zero available blocks after completion while `/mnt` retained
  about 1.1 TB.

## Quick Start

```bash
export PYTHONPATH=src

python scripts/runtime_v2.py init \
  --run-dir output/runtime-v2-run

python scripts/runtime_v2.py submit \
  --run-dir output/runtime-v2-run \
  --task-id openmeetings-cve \
  --task-file task.txt \
  --project-key apache/openmeetings

python scripts/runtime_v2.py run \
  --run-dir output/runtime-v2-run \
  --workers 8

python scripts/runtime_v2.py status \
  --run-dir output/runtime-v2-run
```

`run` auto-detects `traecli`, `traex`, then `codex`. Use
`--agent-command <command>` or `RUNTIME_V2_AGENT_COMMAND` to override it.
Use `--audit-command` to select a separate TraeX or Codex command for the
independent runtime claim audit.

The Agent receives full shell, network, Git, package-manager, and Docker
capability. The task text may mention a repository, revision, vulnerability
location, compile image, or Dockerfile, but these are suggestions rather than
platform-enforced inputs. The Agent may clone source, install tools, repair
dependency conflicts, pull database or middleware images, and generate a single
image, Compose topology, or launch scripts.

## Submission Contract

The Agent writes a candidate JSON file in its attempt directory and invokes the
attempt-specific command included in its prompt. The equivalent direct command is:

```bash
python -m route_hacker.runtime_v2 submit-result \
  --run-dir output/runtime-v2-run \
  --task-id openmeetings-cve \
  --attempt-id 1 \
  --candidate /absolute/attempt/path/candidate-result.json
```

The candidate uses this contract:

```json
{
  "primary_image": "runtime-v2/example:latest",
  "launch": {
    "type": "compose",
    "file": "compose.yaml",
    "primary_service": "app"
  },
  "probes": [
    {
      "type": "http",
      "url": "http://127.0.0.1:8080/"
    }
  ]
}
```

`launch.type` may be `image`, `compose`, or `script`. Supported probe types are
`http`, `tcp`, `command`, `exec`, `log`, and `liveness`.

`submit-result` validates schema, launch-specific fields, workspace paths, and
probe arguments. Rejected submissions return a structured reason and a nonzero
exit code. The same Agent attempt can repair and resubmit. An accepted submission
atomically creates the normalized `result.json` consumed by the verifier.

## Verification

Verification has three ordered stages:

1. Metadata submission accepts and persists a candidate.
2. The mechanical verifier cleans attempt-owned resources, independently starts
   the accepted runtime, and executes its probes.
3. An independent TraeX/Codex auditor checks whether the passed probes actually
   support the runtime-ready claim.

The auditor defaults to pass when the mechanical evidence supports the claim. A
reject is valid only when it includes reproduction commands, concrete
observations, and evidence under the attempt directory. Invalid output, timeout,
or auditor execution failure is recorded as `audit_infrastructure_failed`.

Final task states remain:

```json
{"status": "runtime_ready"}
```

or:

```json
{
  "status": "failed",
  "reason": {
    "stage": "metadata | launch | probe | audit | infrastructure",
    "code": "stable_machine_code",
    "message": "human-readable explanation",
    "evidence_path": "/path/to/artifact"
  }
}
```

## Attempts

Each task receives at most three construction attempts:

1. `initial`: a new workspace with the original task.
2. `warm`: the initial workspace plus previous logs and results.
3. `clean`: a new workspace with only the original task.

If all attempts fail, a final Agent reads their records and writes diagnosis
artifacts without attempting another build.

Each attempt uses a fresh ephemeral Agent session. Warm retries receive the
previous workspace and record paths explicitly; clean retries do not.

The queue is stored in `<run-dir>/queue.db` using SQLite WAL. `--workers`
controls global concurrency. Tasks with the same non-empty `project_key` are
not run concurrently.

Each attempt stores all submission checks, the accepted `result.json`,
`verification.json`, `audit.json`, and a structured reason when it fails.

## Reviewing an Earlier Run

Prepare a new run without modifying the source run:

```bash
python scripts/runtime_v2_review.py prepare \
  --source-run /path/to/original-run \
  --review-run /path/to/new-review-run
```

Run the new queue with the normal local or SSH worker. After it reaches terminal
states, generate the comparison:

```bash
python scripts/runtime_v2_review.py report \
  --review-run /path/to/new-review-run
```

The review report includes old-to-new status transitions and grouped failure
reason stages/codes. Use repeated `--task-id` or `--limit` to prepare a smoke
subset before reviewing the full queue.
