# Runtime v2 environment repairs

This reviewed subset preserves **236 repair/configuration files (274,423 bytes)**
from the final attempts of `runtime-v2-review-full143-20260815T120149Z`:
85 Dockerfiles/variants, 83 shell files, 11 source diffs, 27 runtime
harness/bootstrap files and 30 configuration files. Harnesses and health checks
are not automatically complete upstream applications or vulnerability witnesses.

[runtime-environment-index.json](runtime-environment-index.json) links recipes to
their task, final attempt, source digest, available Git revision and historical
verification receipts. Of the 236 files, 234 retain exact bytes; two stop scripts
have recorded host-root parameterization. None was executed for preservation.

## Historical evidence, not a fresh runtime test

- 143 tasks reached historical `runtime_ready` in this review run.
- All 152 attempts remain indexed: 143 `passed` and nine `failed`.
- Final launch types: 76 image, 34 compose, 33 script.
- Mechanical and runtime-audit outcomes are retained separately. Public probe
  fields contain types, return/status codes and timing, not response bodies,
  cookies or credentials. These outcomes do not certify a PoC or vulnerability.

The earlier unified143 run's 25-ready/118-failed result is a different snapshot,
not this final review result. Exact private recovery data preserves the review
attempts, queue snapshot, receipts, selected source changes and framework copy.

## What is not restored by this Git directory

The index keeps 390 further candidate files by source hash without publishing
their contents: sensitive or potentially sensitive configurations, large source
changes, unresolved path references, and 185 copied upstream files not established
as environment repair assets. Their preserved private copies were not deleted.

Forty tasks have no public final-attempt recipe file. For 37 image/compose tasks,
no generated Dockerfile was identified in the preserved final-attempt candidate
set. This may require an upstream recipe, an earlier attempt or a prebuilt image;
it is not a claim that no such recipe ever existed.

On 2026-09-30, only 12 of the 76 image-launch tags resolved in the current default
Docker daemon. Compose and script metadata have different meanings; descriptive
script values must not be counted as missing image tags. No image layers were
exported, no build was repeated and no application was restarted. The public
subset is therefore **not 143 self-contained, currently runnable environments**.

Read each task's `rebuild_gaps`, required external inputs and source provenance
before reuse. Historical scripts may stop processes or replace files; review in
an isolated copy, never in the original workspace or with production credentials.
