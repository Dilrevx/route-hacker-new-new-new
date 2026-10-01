# Historical build and runtime repairs

This archive preserves the work needed to make historical targets compile or
run: project-specific Dockerfiles, dependency and toolchain choices, source
patches, launch/initialization scripts, repair decisions, and evidence indexes.
It complements the [previous-method model archive](../previous-method/README.md).
It is **not** a newly executed benchmark or a claim that every environment can
be rebuilt today.

Start with the [Chinese repair guide](REPAIR_GUIDE.zh-CN.md) for concrete examples
and links to the existing notes. This is a **repair-knowledge archive**, not a
full environment backup. An existing document that explains the problem, repair
steps or commands, and observed outcome is sufficient; large dependency bundles,
images, and raw logs do not have to be uploaded alongside it. Where a note is
incomplete, retained Dockerfiles, patches, and scripts provide supporting detail.
No new private upload destination is required for this scope.

## Keep the repair families separate

| Family | Historical scope | What the evidence means |
| --- | --- | --- |
| [Legacy builds](legacy-builds/) | 317 catalog rows; 254 Dockerfiles and 43 build notes | Historical catalog flags and recipe snapshots; not independently revalidated runtime results |
| [Compile fleet / CodeQL repair](codeql-compile/) | 137 fleet cases; 242 repair decisions and 11 compact wave ledgers | Build or CodeQL database construction, not vulnerability detection or runtime confirmation |
| [Runtime v2](runtime-v2/) | 236 repair/config files; 143 tasks, 152 attempts (143 passed, 9 failed) | Historical mechanical verification and audit receipts; not a new startup test or PoC confirmation |
| [Source/runtime experiments](source-runtime/) | 41 files; 22 case directories: 20 `source_inserted`, 2 Superset controls | Separate synthetic-insertion/control experiments; do not relabel them as untouched vulnerable-source builds |

These scopes overlap, use different units, and come from different dates. Do not
sum their counts into a single number of successfully reproduced vulnerabilities.
Failure records are part of the preserved work, not discarded examples.

## Reuse a repair

1. Find the project and historical revision/case in that family's index. An
   abbreviated or numeric identifier is not necessarily a verified Git commit.
2. Read the recipe, source provenance, historical outcome, and external input
   requirements together. Some fixes build only selected modules, use a shim,
   inject a class into a release package, or modify source; these are not
   equivalent to a full unmodified-source build.
3. Recreate the source and dependencies in a disposable, isolated workspace.
   Review historical commands first: they can remove files, fetch dependencies,
   disable checks, assume a local proxy, or start intentionally vulnerable software.
4. Rerun compilation and runtime verification separately, with fresh receipts.
   Archive verification below only checks preservation integrity.

No archived shell script, Dockerfile, PoC, build, or service is executed by the
archive verifier. The archive does not provide a blanket bulk-run command.

```bash
python3 baselines/environment-fixes/tools/verify_archive.py
python3 -m unittest discover -s baselines/environment-fixes/tools -p 'test_*.py'
```

## Existing implementations

- [Constrained build/CodeQL repair](../../new-impl/compile-builder-v2/).
- [IRIS reproduction and recorded 213-case coverage](../../new-impl/repro/iris_native_traex/).
- [Runtime v2 verifier](../../new-impl/runtime-v2-verifier-redesign/).
- [PoC runner](../../new-impl/poc-agent-runner/).

The archived recipes record concrete repair work outside those implementation
modules. Merely preserving a framework or a success count would not preserve the
individual fixes.

## Preservation and publication boundaries

The initial archive did not change or delete original server files. Exact private recovery copies
are separate from this reviewed public subset. Raw databases, model transcripts,
HTTP payloads, credentials and large source/dependency trees are not published
wholesale. Per-family manifests distinguish exact files, edited publication
copies, held files and dependencies still only on the server.

Container tags alone do not preserve image layers. A historical successful
receipt does not mean its image or all build inputs remain available. Large
offline dependency bundles and Docker build contexts must **not** be deleted on
the assumption that this small Git archive backs them up.

Project patches and excerpts retain their upstream provenance and licensing;
this archive does not relicense third-party code. Historical local paths and
product names are provenance, not portable defaults or an anonymized submission.

See [archive manifest](archive-manifest.json) and
[verification receipt](verification-receipt.json) for the delivered file checks.
The [preservation inventory](preservation-inventory.json) distinguishes verified
private recovery copies from the public subset and approximately 30.31 GB of
identified dependency files still only on the server, plus unpreserved directory
contexts. These are informational backup boundaries, not outstanding uploads for
the repair-knowledge task. Neither the public archive nor this inventory
authorizes their deletion.

On 2026-10-01, seven separately backed-up Akka input archives (148,029,444 bytes)
were removed from their exact server paths after fresh local and remote hash
verification. Their complete private local copies remain. The [cleanup record](../../docs/research-history/remote-cleanup-20261001.json)
provides the exact restore mapping; restore those inputs before reusing their
build recipes. No build context directory, recipe, running environment or
unbacked dependency was removed by that cleanup.
