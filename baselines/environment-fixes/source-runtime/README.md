# Historical source/runtime recipes — SOURCE-INSERTED EXPERIMENTS

This archive preserves **20 `source_inserted` case histories and two Superset base/patched-control histories**. It does **not** claim reproduction of the original vulnerable applications at exact vulnerable revisions. A historical CVE label identifies an experiment family, not proof that an unmodified upstream release was reproduced.

The archive contains 41 unchanged historical script, build-command and patch files (142,479 bytes). `MANIFEST.json` records each source hash, published hash, source/version provenance and safety warning. `CASE_INDEX.json` keeps all 22 cases, including failures and cases with no public recipe; it supplies no merged success count. Original raw logs, credentials, runtime responses, model conversations and application databases are not included.

## Safety: do not run this archive directly

These are archived inputs, **not a batch runner or turnkey environment**. Some files contain recursive deletion, process termination, network downloads, source insertion and local vulnerability probes. All files are supplied as non-executable archive files. Read every command first, replace historical paths as appropriate, and review/run only in a disposable isolated copy with no credentials or production access. Never point them at the original working tree or a shared dependency directory. No build, application launch or probe was executed while preparing this archive.

Fixed historical filesystem paths remain unchanged to preserve provenance. They may refer to unavailable inputs or layouts. Preservation of a script does not mean its dependencies are bundled or that it can run independently today. In particular, Java runner/API-shim source files were withheld pending license/provenance review; recipes that depend on them are consequently incomplete in this public subset.

Files ending in `.command` are historical command records, often mixed with Java/Maven/Ant version output. They are not shell scripts. Six of seven fail a whole-file Bash syntax parse for that reason; the records are preserved unchanged, not repaired into runnable scripts. All three exported `.sh` files and all 14 Python files pass syntax-only checks.

## Keep the evidence levels separate

- **Compile/build return code**: describes that individual historical command, not a full reproducible project build.
- **Source-runner witness**: applies to a small runner or shim, not necessarily the real application.
- **Assembled-runtime witness**: may use a source-compiled class or inserted configuration with an official distribution; it is not an unmodified exact-source build.
- **Original application reproduction**: is not asserted by this archive.

Pulsar explicitly has two different records: a source-runner `TP_RUNTIME_VERIFIED_SOURCE_RUNNER` and a full-runtime `FAILED`. The failed attempt inserted a class compiled from 2.8.4 source into fallback 2.8.1 runtime. Do not overwrite this failure with the runner result or with a positive listener count.

JMeter's strict check used a compiled patched class injected into the official 5.4.1 core JAR; the full Gradle build remained blocked. NiFi's `TP_CONFIRMED` used inserted resource files and an assembled official runtime. IoTDB's earlier non-confirming and later strict summaries are both retained as distinct historical observations. Knox's gateway-server build/probe evidence does not erase the interrupted gateway-release packaging attempt.

## Withheld inputs

`HELD.json` contains only provenance/hashes and reasons, not withheld file bodies. Two sensitive-literal-review holds expose only SHA-256 and reason. Ninety-two complete Java runner/API-shim sources remain private because authorship/license provenance was not established. One complete upstream NiFi launch script remains private because the referenced NOTICE/license packaging was not recovered.

Small upstream-derived patches retain their original upstream project/file names; no new license is asserted over those inputs. See `UPSTREAM.md` for the licensing boundary.

## Verification

Every exported file was reread and checked against its private preserved original. `source_sha256` equals `published_sha256`; no executable semantics were rewritten or redacted. Safety review found no credential/token/private-key/header match or non-loopback private-network endpoint in the exported subset. This is a bounded source review, not a guarantee that executing historical code is safe. Python files were parsed without executing them; shell files/command records were syntax-checked only.
