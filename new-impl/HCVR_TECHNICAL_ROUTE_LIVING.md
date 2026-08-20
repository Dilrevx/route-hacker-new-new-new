# HCVR Technical Route

**Document status:** Living technical route
**Last updated:** 2026-08-19
**Current objective:** Retrieve a small, high-recall set of code locations matching a security hypothesis, then use a verifier to establish or reject vulnerability evidence.

## Direction

HCVR uses a two-stage path:

```text
Repository -> generic code views / index -> hypothesis-conditioned retrieval
           -> Top-K reranking -> LLM / CodeQL / Joern verification
```

Embeddings route investigation budget; they do not by themselves prove a vulnerability. The MVP begins with relation-heavy classes such as TOCTOU and evaluates repository-level Recall@K under a fixed verification budget.

The default representation is multi-view and generic:

- Full function and overlapping source windows.
- Bounded AST, CFG, and def-use neighborhoods serialized as program facts.
- Shallow caller/callee context.
- Location score aggregated over all available views.

The recommended retrieval path is:

```text
Bi-encoder or learned prototypes -> Top 200
Cross-encoder or late interaction -> Top 20-50
Precise verifier / agent -> confirmed finding or exclusion rationale
```

The first fixed-category comparison remains: keyword/BM25, pretrained code embedding, binary head, and K learned prototypes. Text-code dual encoders become the next step only after the fixed TOCTOU retrieval task establishes a measurable Recall@K improvement.

## Evaluation Boundary

CWE-Bench-Java/IRIS M11 evidence is maintained separately from HCVR retrieval evidence. The current controlled replay is:

```text
Official CodeQL CWE query over an existing CodeQL DB
  + IRIS v2 EvaluationPipeline-style method-overlap evaluation
```

It is controlled comparator evidence, not native IRIS LLM execution. Existing guideline catalogs are exploratory unless a train-only provenance audit establishes that the release excludes evaluation cases, patches, traces, SARIF, target locations, fix methods, and retrieval outcomes.

## Round Update Record

### Round 0 - Route Formation

**Goal:** Define a reusable hypothesis-conditioned vulnerability retrieval pipeline.

**Decision:** Use generic multi-view program representations, first-stage retrieval, a fine reranker, and a precise downstream verifier. Avoid using CWE-specific `<CHECK>/<USE>` labels as the default retrieval input.

**Next:** Build a TOCTOU MVP with realistic hard negatives and evaluate Recall@10/@30/@50/@100 by repository split.

### Round 1 - Historical M11 Recovery and v8 Continuation

**Goal:** Recover historical M11 controlled-IRIS replay evidence and finish the remaining healthy, M11-eligible CodeQL databases.

**Scope:** Current health inventory contained 63 usable CodeQL databases. Historical controlled replay already covered 49 unique cases. The continuation set was formed as:

```text
healthy DBs ∩ historical M11 preflight-eligible cases ∖ historical completed cases
```

**Action:**

- Recovered the historical producer, batch runner, case auditor, batch auditor, four batch ledgers, and their manifests.
- Verified the historical completion count: 49 cases, with 9 strict method-overlap TP trace cases.
- Built a continuation adapter for v8 database containers. Its identity chain is:
  `declared buggy revision -> GitHub codeload exact-commit URL -> completed fetch log -> source archive hash -> CodeQL YAML source root`.
- Kept historical source/DB assumptions intact; the adapter does not claim that v8 containers expose the old database creation SHA.
- Froze 28 additional eligible cases: 16 CWE-22 and 12 CWE-79.
- Ran one isolated smoke case, then 27 remaining cases with 4 workers and 1 CodeQL thread per case.

**Output:**

- Continuation directory:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr/m11-controlled-iris-replay-continuation-20260818-v1`
- Historical provenance inventory:
  `historical_replay_inventory.json`
- Frozen continuation queue:
  `queue/continuation_queue.jsonl`
- 4-worker run:
  `run-4workers/`
- Independent batch audit:
  `run-4workers-audit-v2/audit_summary.json`

**Verification:**

- All 28 continuation cases completed with zero producer failures and zero identity failures.
- The smoke case produced 53 strict method-overlap flows and passed independent audit.
- The 27-case batch produced 8 strict TP trace cases and 19 completed-no-TP cases.
- All 8 batch TP cases passed independent case audit.
- Aggregate result after continuation: 77 unique controlled replay cases and 18 strict TP trace cases.

**Decision:** The controlled comparator lane now has a larger validated CodeQL-backed cohort. Its release-readiness warning remains: the current continuation batch alone has fewer than 20 audited TP cases. This warning does not invalidate the individual completed runs.

**Next:** Map the 143-case v2 unified evaluation receipt to these 77 M11 cases and to the remaining CodeQL evidence, then keep native IRIS LLM execution as a separately labeled lane.

### Round 2 - Native IRIS With Local TraeX

**Goal:** Run the actual IRIS LLM pipeline on compatible audited Java cases, using local TraeX `DeepSeek-V4-Flash` or `DeepSeek-V4-Pro` rather than treating a healthy CodeQL database as IRIS execution.

**Scope:** The historical v8 materialization audit exposes 63 `iris_shadow_root_ready` rows from 213 historical cases. The v2 unified receipt contains 143 mixed-language/mixed-lineage cases, so it is not assumed to be a native-IRIS denominator until its Java/receipt identities are aligned.

**Action:**

- Implemented a reusable native-IRIS reproduction package at `new-impl/repro/iris_native_traex`.
- The package materializes an isolated copy of the clean IRIS source tree and links only receipt-bound source, CodeQL DB, package-name, and metadata inputs.
- Added a local OpenAI-compatible bridge that invokes `traex exec -m DeepSeek-V4-Flash|DeepSeek-V4-Pro`.
- Added copied-workspace aliases `gpt-traex-flash` and `gpt-traex-pro` so the original IRIS `GPTModel` path is used; no source/sink rules, candidate logic, queries, or evaluation logic are replaced.
- Added artifact-gated single-case and bounded, resumable batch runners.

**Verification:**

- Bridge health and a real local Flash completion succeeded through an SSH reverse tunnel.
- Fresh Retrofit execution: `square__retrofit_CVE-2018-1000850_2.4.0`, `CWE-022`, run ID `native-traex-retrofit-flash-v3`.
- Native IRIS completed in 484.244 seconds with return code 0.
- IRIS generated 6 API-labelling prompts; all 6 local TraeX responses were present and parsed as JSON lists.
- IRIS completed its project-specific CodeQL query, postprocessing, posthoc filtering, and evaluation. All required SARIF/CSV/JSON artifacts were present.
- This smoke produced 0 vanilla and 0 posthoc paths. It proves pipeline execution and must not be reported as a positive detection or a cohort-level metric.

**Decision:** Native IRIS is now a distinct executable lane. Controlled M11 replay remains separately labeled CodeQL comparator evidence.

**Next:** Freeze an identity-aligned cohort from the 63 ready receipts and run it with a bounded local TraeX bridge, then report verified completion, failures, model, and evaluation metrics separately from controlled replay.

### Round 3 - Native IRIS Pro Cohort Dispatch

**Goal:** Execute every currently materializable native-IRIS Java case with `DeepSeek-V4-Pro`, while retaining per-case and aggregate evidence suitable for a later evaluation table.

**Scope:** The frozen source receipt contains 213 historical rows. Exactly 63 rows have `iris_shadow_root_ready` status, with unique case identities across CWE-022, CWE-078, CWE-079, CWE-089, and CWE-094. This is the native IRIS denominator for this dispatch, not the mixed v2 unified denominator.

**Action:**

- Pushed reproducible batch-metrics implementation as `30817e0` (`Add native IRIS batch metrics reporting`).
- Materialized the immutable remote package at:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/iris-native-traex-pro-63-v1/package`
- Wrote `RUN_MANIFEST.json` recording the source commit, cohort size, model alias, and concurrency.
- Started a local OpenAI-compatible TraeX bridge using `DeepSeek-V4-Pro` with bridge concurrency 2, then validated remote access through an SSH reverse tunnel.
- Enqueued all 63 rows into:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/iris-native-traex-pro-63-v1/results/queue.jsonl`
- Started the native IRIS dispatcher with two case workers and one CodeQL thread per case.

**Evidence Outputs:**

- Per-case IRIS outputs and artifact-gated summaries:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/iris-native-traex-pro-63-v1/results/cases/`
- Incremental execution ledger and aggregate status:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/iris-native-traex-pro-63-v1/results/receipts.jsonl`
  and `summary.json`
- Per-call local model metrics:
  `new-impl/repro/iris_native_traex/output/pro-63-v1/traex_pro_calls_63_v1.jsonl`
- Paper-facing merged metrics are generated from those two JSONL sources with:
  `summarize_native_iris_metrics.py`

**Verification:** Before dispatch, the remote package passed `py_compile` and all three reproduction tests. Queue cardinality is exactly 63. Two isolated workspaces are active in `src/iris.py`; completion remains gated on zero exit, complete final IRIS artifacts, and valid JSON label responses.

**Decision:** Report only artifact-gated completed cases from this cohort. Token accounting is the TraeX CLI-reported total when available; no input/output token split is inferred.

**Next:** Monitor the 63-case dispatcher to completion, run the metrics merger, and align the completed native-IRIS subset to the v2 unified evaluation receipt without conflating it with controlled CodeQL replay.

### Round 4 - Freeze v2 QA IRIS Identity and Harden Native Dispatch

**Goal:** Establish the authoritative IRIS-derived denominator for the 143-case v2 paper-eval QA receipt and make native dispatch resumable when inputs or individual cases fail.

**Scope:** The v2 QA receipt reports 45 IRIS-derived cases but stores only the bucket count. The 143-case allowlist contains 49 cases carrying an `iris` type tag, while the official IRIS `project_info.csv` contains 213 historical projects. Identity selection uses only the frozen allowlist, official IRIS project metadata, and the two official fix tables.

**Action:**

- Compared the normalized v2 allowlist identities with official `project_info.csv`, `fix_info.csv`, and `fix_info_source_sink.csv`.
- Defined the hard-join rule as:
  `v2 allowlist ∩ project_info ∩ (fix_info ∪ fix_info_source_sink)`.
- Added `build_qa_iris_manifest.py`, which freezes the selected identity, source-table evidence, v2 checkout revision, official buggy commit, preflight status, and exact source/CodeQL/package paths.
- Added path admission checks before materialization and preserved source/revision metadata in every batch receipt.
- Changed batch failure handling so input, materialization, process-spawn, malformed-summary, and worker exceptions remain retryable per-case receipts while later cases continue.
- Updated the native IRIS README and tests to use the explicit manifest protocol.

**Output:**

- Frozen manifest:
  `new-impl/repro/iris_native_traex/manifests/qa_iris_manifest.v1.jsonl`
- Manifest summary:
  `new-impl/repro/iris_native_traex/manifests/qa_iris_manifest.summary.v1.json`
- Selection result: 45 cases, composed of 21 `fix_info` hits and 24 `fix_info_source_sink` hits.
- Explicit tag-only exclusions: `apache__activemq-artemis::CVE-2025-27427`, `apache__felix-dev::CVE-2025-25247`, `apache__tomcat::CVE-2025-24813`, and `jenkinsci__oic-auth-plugin::CVE-2025-24399`.
- Existing preflight status: 17 `codeql_db_created`, 28 `codeql_db_failed`; all 45 have a preflight row.

**Verification:**

- The manifest builder passed `py_compile` and produced exactly 45 unique rows.
- Official table hashes were recorded in the summary:
  `project_info.csv` `be336f...22da`, `fix_info.csv` `34d320...06a45`, and `fix_info_source_sink.csv` `0bc6e9...6942d`.
- The v2 allowlist hash is `3b3f452c...8502d`.
- Forty-four selected cases have matching v2 checkout and official buggy revisions; one retains an explicit revision difference for audit.
- Native IRIS execution was not started during this round because the current local workspace does not contain the remote source/DB paths; the 28 unavailable DBs remain input-status evidence rather than fabricated runnable cases.

**Decision:** The QA IRIS denominator is now traceable and frozen as 45 identities. The four tag-only cases are excluded from native IRIS scope. Native execution may admit only rows whose manifest paths pass on the execution host; unavailable rows remain retryable and visible.

**Next:** Push only the native IRIS reproduction package, transfer the frozen manifest and its source-table/preflight evidence to the execution host, run the 17 existing CodeQL-backed cases with bounded concurrency, and separately record the 28 input-unavailable cases until their DB build status changes.

### Round 5 - Validate the Frozen Manifest Contract

**Goal:** Verify that the repaired dispatcher accepts the frozen manifest exactly as generated and that local validation does not start a native batch.

**Scope:** Native IRIS manifest admission, materialization validation, batch failure isolation, and local repository hygiene.

**Action:**

- Compared the manifest revision schema with both the materializer and batch admission code.
- Corrected batch admission to require the manifest's `revisions.v2_checkout_revision` field.
- Added a regression test covering admission of a valid v2 revision record.
- Ran direct materialization tests, script compilation, whitespace validation, and actual 45-row manifest admission against the 143-case allowlist.

**Output:**

- Six direct materialization/dispatcher tests passed.
- The 45-row manifest was accepted with hash
  `320790700c5a41a311003635f2973e50f0085ca6939ed91057bd9835d96db0cd`.
- The manifest summary remained consistent: 17 `codeql_db_created` and 28 `codeql_db_failed`.
- No native IRIS batch was started during local validation; the only long-running process is the reusable local TraeX bridge.

**Verification:** All native IRIS scripts and tests passed `py_compile`; `git diff --check` passed; the actual manifest passed `validate_iris_manifest` with 45 rows and the frozen allowlist.

**Decision:** The native dispatcher is ready to run on a host where the manifest's source, CodeQL DB, and package-name paths exist. Input-unavailable cases remain explicit retryable receipts and are not silently dropped.

**Next:** Commit and push only the native IRIS package, frozen manifest, validation tests, README, and living route document. Run the native batch only after the execution host has the referenced inputs.

### Round 6 - Stabilize Native IRIS Transport and Retry Runnable QA Cases

**Goal:** Recover native IRIS execution for the frozen 45-case v2 QA manifest after the first remote batch reached real LLM labelling but lost the local TraeX bridge connection.

**Scope:** The immutable QA manifest remains the 45-case source of truth with hash `320790700c5a41a311003635f2973e50f0085ca6939ed91057bd9835d96db0cd`. A live filesystem admission on the execution host found 20 rows with directory/file paths present and 25 rows with missing source inputs. The 20-path count is only a provisional runnable count: a CodeQL directory can still be an interrupted database creation.

**Action:**

- Audited the completed `qa-iris-v2-45-a2` receipts and a representative Retrofit stderr trace.
- Confirmed that the previous generated-adapter syntax failure was fixed, then identified the second failure as `httpx.ConnectError: [Errno 111] Connection refused` during IRIS's first native API-labelling batch.
- Kept the original copied `src/iris.py` stages intact and added only bounded OpenAI-transport retries to the copied `src/models/gpt.py` adapter. The adapter retries transient completion failures using `IRIS_LLM_MAX_ATTEMPTS` and `IRIS_LLM_RETRY_DELAY_SECONDS`.
- Moved the local TraeX bridge and SSH reverse tunnel into persistent tmux sessions with SSH keepalive settings. Both endpoints expose and repeatedly pass `/healthz`.
- Added a DB completion gate in the batch dispatcher. Admission now requires a CodeQL database directory to contain both `codeql-database.yml` and `db-java`; interrupted creation directories are recorded as input failures before any model call.
- Pushed the transport retry change as `712161a` and the partial-DB admission gate as `c2bca99`.

**Verification:**

- Direct native-IRIS regression tests and `py_compile` passed after each change.
- The fresh Pro smoke case `square__retrofit::CVE-2018-1000850` completed as `completed_verified` in 321.963 seconds.
- The smoke used the original IRIS entrypoint `src/iris.py`, generated 6 native API-labelling prompts, stored 6 valid JSON-list responses, and completed all required extraction, query, postprocessing, posthoc, and evaluation artifacts.
- The smoke artifact gate verified `results.csv`, `results.sarif`, `results_pp.sarif`, posthoc SARIF/JSON/stats, and final JSON.
- The `a3` bridge recorded 6/6 successful Pro calls for this smoke. Token values remain `null` when the TraeX CLI does not print a reported total; no token split is inferred.
- Axis `CVE-2023-51441` demonstrated why directory-only admission is insufficient: its path contains an interrupted DB creation without `db-java`, so IRIS correctly rejected it before LLM labelling.

**Current Execution State:**

- The verified Retrofit smoke is retained separately at:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a3-smoke/`.
- A derived retry manifest contains the remaining 19 path-present candidates after excluding the verified Retrofit smoke. It is hashed as `0411905bf1cfd537ccc9b625340867eeefefd8828c9b41917379dc50cd22e4ec`.
- The persistent retry dispatcher uses attempt ID `qa-iris-v2-45-a3-retry`, eight project workers, eight IRIS label threads per project, a bridge concurrency cap of eight, and a 7,200-second per-case timeout.
- The first partial-DB case produced one explicit non-verified receipt. Remaining cases continue independently in the dispatcher; completion must still be determined only from each per-case artifact gate.

**Decision:** Native IRIS transport is now verified end-to-end with the real Pro backend. The experiment separates completed CodeQL databases, partial DB artifacts, missing inputs, and artifact-gated IRIS results. It does not promote path-present rows to successful runs.

**Next:** Let the retry dispatcher finish, classify every receipt by verified completion or evidenced failure, apply the DB completion gate to any future queue rebuild, merge bridge and receipt metrics, and update the v2 QA alignment ledger.

### Round 7 - JSON-List Transport Recovery for Native IRIS

**Goal:** Recover otherwise complete native IRIS runs whose API-labelling responses violated the JSON-list contract, without replacing IRIS logic or postprocessing model output.

**Scope:** Several v2 QA runs completed native `src/iris.py` and produced the required CodeQL artifacts, but their wrapper receipts remained non-verified because one or more raw API-labelling responses contained explanatory text or a Markdown-fenced JSON list. The original IRIS API-labelling prompt requests a JSON list but does not pass `expect_json=True` to `GPTModel.predict`, so the OpenAI bridge cannot infer that response shape by itself.

**Action:**

- Extended only the copied `src/models/gpt.py` transport adapter generated by `materialize_iris_case.py`.
- The adapter recognizes original prompts that explicitly request a JSON list, validates the returned text using the same accepted shapes as the strict runner audit (a raw list or one complete `json` fence), and makes at most a bounded follow-up model request when the response is invalid.
- The follow-up retains the original system and user prompts and appends a short format correction. It never extracts, repairs, or synthesizes a list from the first model response.
- Preserved the original IRIS entrypoint, candidate collection, query generation, CodeQL analysis, posthoc filtering, and evaluation.
- Added regression coverage for invalid-text retry, preservation of the original prompt, generated-adapter syntax, and acceptance of complete fenced JSON lists without unnecessary retry.

**Verification:**

- Pushed the initial bounded retry implementation as `503c427` (`Retry invalid IRIS JSON-list model responses`).
- Re-materialized and ran `alibaba__one-java-agent::CVE-2022-25842` in an isolated workspace with `DeepSeek-V4-Pro`, one native IRIS thread, and the corrected bridge.
- IRIS processed 300 API candidates in 10 native labelling batches. The bridge recorded 28 completed calls over the full native run; this exceeds the ten first-pass API-label batches because bounded format retries and later-stage/posthoc calls are recorded separately.
- The run completed all native stages with return code 0 and passed the strict wrapper gate as `completed_verified`.
- The verified receipt records 41 labelled APIs (8 sources, 8 sinks, 25 taint propagators), 25 vanilla paths, 4 vanilla TP paths, 4 posthoc paths, and 4 posthoc TP paths. It has complete CSV/SARIF/JSON artifacts and all 10 API-label responses accepted as JSON lists by the audit.
- Evidence root:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/one-java-jsonlist-retry-a2/results/summary.json`

**Decision:** JSON shape is a transport reliability concern, not a reason to weaken the native IRIS completion gate. Future retries reuse the adapter and remain independently artifact-gated; existing in-flight runs are not interrupted.

**Next:** Let the active a6/a7/Hutool runs finish, then re-materialize the remaining JSON-format-only failures with this adapter under the bridge concurrency cap and merge only `completed_verified` receipts.

### Round 8 - Native IRIS Admission Audit and Bounded Format-Retry Queue

**Goal:** Continue improving runnable v2 QA coverage without treating an available source tree or an incomplete CodeQL directory as evidence that native IRIS can run.

**Scope:** The frozen v2 QA manifest contains 45 identities. The original dispatcher recorded 25 `input_unavailable` rows and 20 initially runnable rows. The audit distinguishes native-IRIS input compatibility from the separate ability to build a CodeQL database.

**Action:**

- Audited every original `input_unavailable` receipt against its frozen manifest paths and blockers.
- Found that 24 of the 25 rows also lack one or more native IRIS prerequisites: package-name metadata, official IRIS project/fix-table identity, or a supported IRIS query name. Rebuilding only a CodeQL DB cannot make those rows valid native IRIS executions, so they remain explicit out-of-scope/input-unavailable evidence.
- The remaining input-unavailable row has a complete CodeQL DB but lacks the package-name input required by original IRIS; it also remains unadmitted.
- Rechecked Compile Builder v2 inputs. Four exact-source DB-failed cases were eligible for the constrained repair dispatcher: Tika produced a fresh valid CodeQL DB and a verified native IRIS run; Axis and Spring Cloud Config had no safe action; Keycloak's proposal was rejected by the approved-environment validator.
- Added explicit forwarding of `--label-api-batch-size` and `--label-func-param-batch-size` from the batch dispatcher to every single-case runner. The change is tested and pushed as `a709855`.
- Created a derived eight-case manifest containing only cases whose original native IRIS execution produced all final artifacts but failed only the strict JSON-label audit. The already verified One Java Agent case is excluded.
- Started a one-worker a8 retry only for two cases not already active or queued by older dispatchers. Native IRIS may hold HTTP connections while its own prompt batches are pending; the authoritative global bound is therefore the bridge's eight-slot semaphore, which caps actual `traex exec` completions even when additional requests queue.
- Hardened the batch dispatcher for interruption recovery: each case workspace has an exclusive lock, and a resumed, unlocked partial workspace is preserved under a timestamped sibling name before rematerialization. This keeps partial evidence while allowing a clean native retry.

**Verification:**

- The a8 admission receipt and derived manifest are stored at:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a8-jsonlist-admission/`.
- The active a8 subset and launch contract are stored at:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a8-jsonlist-retry/`.
- The first a8 workspace was materialized from the current adapter, compiled successfully, and reached the original IRIS CodeQL extraction stages with explicit label batch sizes `30` and `20`. Bridge metrics showed successful model calls during the run; all token fields remain null when TraeX does not report a total.

**Decision:** Native IRIS coverage is expanded only where original IRIS metadata, exact source, a complete CodeQL database, and a package-name file all exist. Cases missing official IRIS inputs are retained in the v2 denominator as documented input failures rather than being transformed into a different benchmark.

**Next:** Continue monitoring a6/a7/Hutool/a8. Resume interrupted cases through a fresh attempt namespace, then admit the next non-overlapping JSON-label retry from the frozen eight-case queue; merge only strict `completed_verified` receipts.

### Round 9 - Interruption-Safe Retry and Bridge-Level Concurrency Enforcement

**Goal:** Make native IRIS retries resilient to an interrupted case workspace while preserving original IRIS execution, evidence, and the global model-capacity constraint.

**Scope:** The a8 JSON-list retry was intentionally interrupted during MyFaces observation. Sling continued in the existing a8 attempt. MyFaces required a clean retry namespace because the interrupted workspace cannot be treated as a completed result.

**Action:**

- Verified that original IRIS constructs all prompt batches before calling its model adapter; `--num-threads` controls concurrent calls within that native `predict()` stage.
- Verified that the TraeX OpenAI bridge owns the authoritative global `BoundedSemaphore(8)`. Extra HTTP clients can wait at the bridge, but no more than eight `traex exec` model calls execute concurrently.
- Added per-workspace exclusive locks to the batch dispatcher. A second dispatcher receives an auditable `workspace_busy` receipt instead of racing a live case.
- Added interruption-safe `--resume`: an unlocked partial workspace is moved to a timestamped `.interrupted-*` sibling and the case is rematerialized cleanly. The partial workspace is preserved rather than deleted.
- Preserved a8 Sling as its original native attempt and launched MyFaces in separate attempt `qa-iris-v2-45-a9-myfaces-jsonlist-retry`, with a single-row derived manifest and an independently recorded result directory.
- Corrected the a9 launch manifest before execution by parsing and validating the single JSONL row; the initial malformed wrapper output did not start IRIS and was replaced before the retry entered `src/iris.py`.

**Verification:**

- `run_native_iris_batch.py` passed `py_compile`, existing transport/strict-gate tests, the batch concurrency and partial-DB gates, and a new interruption-workspace quarantine regression test.
- The change is pushed as `796cc88`.
- During observation, Sling and MyFaces both produced successful bridge-completion metrics. Raw label response files remain pending until each original IRIS `predict()` batch completes; this is native IRIS batch behavior.
- The a8 stale MyFaces `materialization_failed` receipt is retained as interruption evidence and is not counted as a native IRIS outcome for the independent a9 attempt.

**Decision:** The bridge semaphore is the enforced model-concurrency contract. Project-level worker counts provide scheduling context only. Interrupted retries always receive a fresh attempt identity or explicit `--resume` recovery, so no partial workspace or stale receipt can silently become a successful run.

**Next:** Wait for a8 Sling and a9 MyFaces to write their strict completion receipts. Validate original IRIS return code, all required artifacts, and every raw JSON label before counting either result as `completed_verified`; then select the next frozen JSON-label retry that is not active.

### Round 10 - Verified Sling JSON-List Retry Completion

**Goal:** Close the a8 Sling retry only after the native IRIS runner, artifact gate, and label-response audit agree on a complete result.

**Scope:** This round covers only `apache__sling-org-apache-sling-servlets-resolver::CVE-2024-23673` (`case::aec41e376e99c5fd0a40`) in attempt `qa-iris-v2-45-a8-jsonlist-retry`. The stale a8 MyFaces materialization receipt remains interruption evidence and is excluded from this case result.

**Action:**

- Observed the copied original `src/iris.py` complete its CodeQL, posthoc-filter, and evaluation stages without intervention.
- Read the final a8 receipt and independently checked the strict gate fields rather than inferring success from the presence of intermediate SARIF files.
- Distinguished API-labelling response files from historical empty raw files and posthoc-filter responses. Only the 18 prompt responses dispatched by the API-label stage are subject to the JSON-list contract; posthoc uses its own native response shape.

**Verification:**

- The Sling receipt is `completed_verified` with `runner_returncode: 0`.
- Its artifact gate reports every required artifact present: primary `results.csv`, `results.sarif`, `results_pp.sarif`, final `results.json`, plus posthoc `results.json`, `results.sarif`, and `stats.json`.
- Its label-response audit reports `all_valid: true` for all 18 dispatched API-label prompts.
- The verified evidence remains at:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a8-jsonlist-retry/`.

**Decision:** Count Sling as one native-IRIS `completed_verified` result. Do not widen the JSON-list audit to unrelated historical or posthoc raw-response files, because that would contradict the original API-label contract and create a false failure.

**Next:** Continue MyFaces a9 until it emits its independent strict receipt; then apply the same return-code, artifact, and dispatched-label audit before merging it into coverage metrics.

### Round 11 - Verified MyFaces Native IRIS Retry Completion

**Goal:** Independently close the interruption-recovered MyFaces retry using the same strict native-IRIS completion contract as Sling.

**Scope:** This round covers `apache__myfaces::CVE-2011-4367` (`case::49c75f67f869cd0420fd`) in the fresh attempt `qa-iris-v2-45-a9-myfaces-jsonlist-retry`. It does not reuse the interrupted a8 workspace or its stale materialization receipt.

**Action:**

- Let the newly materialized copied original `src/iris.py` finish its 52-prompt API-label phase, CodeQL analysis, posthoc-filter model calls, and final evaluation without case-specific intervention.
- Verified the final receipt against the runner's exact prompt-to-response audit mapping. This deliberately excludes old IRIS empty placeholder files whose names do not correspond to a dispatched prompt and excludes posthoc responses, which have their own native schema.

**Verification:**

- The a9 receipt is `completed_verified` with `runner_returncode: 0`, `verified_completion: true`, and elapsed time `3713.433` seconds.
- The artifact gate confirms primary CSV/SARIF/postprocessed SARIF, final JSON, and posthoc SARIF/JSON/statistics are all present.
- The strict runner audit independently rechecked all 52 dispatched API-label prompt/response pairs: 52 prompts, 0 invalid JSON-list responses.
- Native IRIS recorded 1,547 candidate APIs, 38 labelled sources, 10 labelled sinks, 160 taint propagators, 20 vanilla paths, 3 posthoc paths, and 15 successful posthoc LLM calls.
- Evidence root:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a9-myfaces-jsonlist-retry/`.

**Decision:** Count MyFaces as a second independently verified native-IRIS result recovered through the general interruption-safe dispatcher and bounded JSON-list transport retry. The a8 stale MyFaces receipt remains retained provenance only and is not a competing result.

**Next:** Merge a8 Sling and a9 MyFaces into the v2 QA native-IRIS coverage ledger, while remaining in-flight historical a6/a7 cases continue under the bridge-level eight-request cap.

### Round 12 - Per-Case Native IRIS Coverage Audit and a10 Retry Queue

**Goal:** Expand native-IRIS coverage only for frozen v2 QA cases whose remaining failure is transport-format reliability, while keeping source identity, IRIS metadata, and CodeQL database validity explicit.

**Scope:** Audited every row in the frozen 45-case native-IRIS manifest against all prior native-run receipts, current CodeQL database layout, and Compile Builder v2 repair receipts. This round does not invent IRIS project metadata, package-name files, queries, or source revisions.

**Action:**

- Reused the existing Compile Builder v2 audit for the four cases whose only manifest blocker was a missing CodeQL database. Tika produced a repaired complete database and already reached `completed_verified`; Axis, Keycloak, and Spring Cloud Config remain explicit non-successes because their locally constrained model decisions were respectively no-safe-action, rejected, and no-safe-action.
- Distinguished 17 currently complete CodeQL databases from partial or absent database directories using both `codeql-database.yml` and `db-java`.
- Found 11 of those 17 cases already have at least one strict `completed_verified` native-IRIS receipt. Three more are in existing a6/a7 native runs.
- Selected exactly three non-active cases with complete CodeQL DBs, exact source, official IRIS project/fix metadata, package-name files, and final artifacts from prior runs whose only failed gate was API-label JSON-list validity:
  `asf__commons-io::CVE-2021-29425`,
  `dromara__hutool::CVE-2018-17297`, and
  `vert-x3__vertx-web::CVE-2018-12542`.
- Created the frozen a10 derived manifest with SHA-256 `852f75b6da615e60bf68234115ac52bd99e7f26e33614aebf205e16f59ec819d` and launched it with two project workers, one native IRIS label thread per project, a 14,400-second case timeout, and the bridge-level eight-request cap.

**Verification:**

- The deployed materializer, single-case runner, and batch dispatcher match the checked-in SHA-256 values and pass `py_compile`.
- Before dispatch, every a10 row was checked for source directory, package-name file, no manifest blockers, and a complete CodeQL layout.
- The a10 dispatcher materialized Commons IO and Hutool into clean isolated workspaces and invoked the copied original `src/iris.py`; Vert.x 2018 remains queued behind the two-worker bound.
- The a10 evidence root is:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a10-jsonlist-coverage-retry/`.

**Decision:** The a10 queue targets a single general transport failure class, not a case-specific recovery. Cases missing official IRIS prerequisites or whose Compile Builder v2 repair was safely rejected remain recorded as non-admitted rather than being converted into synthetic native-IRIS inputs.

**Next:** Strictly validate a10 receipts as they arrive, then inspect the existing a6/a7 in-flight cases for completion or a reusable transport/root-cause classification before creating any further queue.

### Round 13 - JSON-List Retry Exhaustion Diagnosis and Transport Hardening

**Goal:** Preserve the strict native-IRIS completion contract while fixing a general LLM-transport reliability gap exposed by the first completed a10 case.

**Scope:** `asf__commons-io::CVE-2021-29425` (`case::e86c4a41fffbe86f19ad`) completed copied original `src/iris.py` in a clean a10 workspace. The run produced all required CodeQL, posthoc, and final artifacts, so the remaining question was whether every original IRIS API/function-parameter labelling prompt received a valid JSON-list response.

**Action:**

- Audited the runner's exact prompt-to-response mapping rather than scanning unrelated raw files.
- Kept Commons IO as `failed_or_incomplete`: native IRIS returned `0` and all required artifacts exist, but one of 33 dispatched label responses was not a standalone JSON list.
- The failing API-label response contained `[]` followed by an explanatory paragraph. It is not repaired, truncated, or rewritten after the fact.
- Traced the issue to the generic copied `GPTModel` transport adapter: its existing bounded correction used only two total attempts. The original API-label system prompt requires JSON-only output, but a model can still violate the contract after one correction.
- Increased the general `IRIS_JSON_LIST_FORMAT_ATTEMPTS` default from `2` to `4`. Each retry preserves the original IRIS system/user prompts and asks only for the required JSON array; it now explicitly states that an empty result must be exactly `[]`.
- Added a regression that simulates two invalid model replies followed by a valid list, proving that the generated adapter retries the same original task and accepts the third response. The change does not alter IRIS candidate collection, query construction, CodeQL analysis, posthoc filtering, evaluation, or any case-specific data.

**Verification:**

- Commons IO receipt:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a10-jsonlist-coverage-retry/cases/case__e86c4a41fffbe86f19ad/summary.json`.
- Its strict result is intentionally non-verified: `runner_returncode: 0`, complete artifact gate, `33` dispatched labels, and one invalid API-label response. Native IRIS recorded 564 API candidates, 133 labelled function-parameter sources, 41 vanilla results, 117 vanilla paths, and 86 successful posthoc calls.
- The materializer, single-case runner, and batch dispatcher pass `py_compile`; the JSON-list retry regression passes when invoked directly with the standard-library test fixture. The local Python installation does not include `pytest`, so the full pytest command was not available.
- Hutool and Vert.x 2018 remain live in the same a10 queue. After Commons IO exited, the two-worker dispatcher automatically materialized and started Vert.x without exceeding the bridge-level eight-request cap.

**Decision:** A successful original IRIS exit and complete final artifacts are necessary but not sufficient. Only `completed_verified` receipts with every dispatched label response valid are counted. The retry change is transport-wide and will be used only by newly materialized isolated workspaces; no existing response is normalized retrospectively.

**Next:** Let Hutool and Vert.x finish under the current bounded queue. Audit each receipt against the same return-code, artifact, and prompt-mapped label gate. Re-materialize Commons IO only after this general adapter change is deployed and the in-flight cases no longer share its prior workspace.

### Round 14 - OpenAI Base-URL Normalization and Clean Retry Boundary

**Goal:** Restore the native IRIS transport contract after a retry-attempt configuration error, without weakening any admission, artifact, or label-response gate.

**Scope:** This round covers the same three preflight-eligible frozen rows selected for a10: Commons IO `CVE-2021-29425`, Hutool `CVE-2018-17297`, and Vert.x Web `CVE-2018-12542`. The remote-to-local TraeX reverse tunnel was re-established before dispatch and passed a remote `/healthz` check.

**Action:**

- Synced the committed four-attempt JSON-list adapter to the remote native-IRIS package and verified matching SHA-256 values plus remote `py_compile`.
- Created a fresh a11 manifest and isolated workspaces; all three rows again passed exact-source, package-name, official IRIS metadata, and complete CodeQL database checks (`codeql-database.yml` plus `db-java`).
- Identified a general base-URL defect before any a11 model completion: the batch launch passed a bridge URL ending in `/v1`, while the single-case runner mechanically appended another `/v1`. OpenAI therefore requested `/v1/v1/chat/completions`, which the local bridge correctly rejected with HTTP 404.
- Preserved all three a11 receipts as failed transport evidence. Their copied original `src/iris.py` instances reached candidate extraction and began API labelling, but no request reached the TraeX bridge metrics and no model output or final IRIS artifact is counted.
- Added `normalize_openai_base_url()` to the generic single-case runner. It accepts either a bridge root URL or a URL already ending in `/v1`, always exporting exactly one OpenAI version path. This is transport normalization only; it does not alter copied IRIS code, prompts, candidate sets, CodeQL queries, label rules, or evaluation.

**Verification:**

- The local bridge and remote forwarded bridge both returned `{"status": "ok", "transport": "traex"}` from `/healthz`.
- Endpoint and traceback evidence show the a11 failure was the duplicate-version URL: the bridge supports `/v1/chat/completions`, while a11 received an untracked 404 before the bridge handler/metrics.
- The URL-normalization regression passed for root, trailing-slash root, `/v1`, and `/v1/` inputs; an empty value raises `ValueError`. The updated runner passes `py_compile` and `git diff --check`.
- a11 evidence root:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a11-jsonlist-4retry/`.

**Decision:** a11 is not a valid native-IRIS result and contributes zero verified completions. Its three rows remain admissible for a clean a12 retry because the failure occurred before any model completion and has a single general transport root cause. The a12 dispatcher will use a fresh output/workspace namespace and the normalized runner.

**Next:** Commit and deploy the URL-normalization fix, launch a12 with the same two-project-worker / one-native-label-thread configuration, verify the first bridge metrics carry the a12 run ID, then count only receipts satisfying original IRIS return-code, full-artifact, and prompt-mapped JSON-list gates.

### Round 15 - a12 Normalized-URL Native IRIS Dispatch

**Goal:** Start a clean native IRIS retry after the generic bridge URL fix and establish that the repaired transport reaches real model completions under the bounded concurrency contract.

**Scope:** a12 reuses the same three independently preflight-eligible frozen rows as a10/a11, but has a new attempt ID, output root, and workspace root. It does not reuse a11 outputs as results.

**Action:**

- Deployed the normalized single-case runner from commit `c6f3df3` to the remote package and verified its SHA-256 matches the checked-in file.
- Before spending model budget, issued a remote POST to `/v1/chat/completions` with an intentionally invalid empty payload. The bridge returned its expected HTTP `400` validation error (`messages must be a non-empty list`), proving the request reached the intended handler rather than a version-path 404.
- Created and validated the three-row a12 manifest. It preserves the prior SHA-256 `852f75b6da615e60bf68234115ac52bd99e7f26e33614aebf205e16f59ec819d`, with complete source, package-name, and CodeQL (`codeql-database.yml` and `db-java`) checks.
- Launched `qa-iris-v2-45-a12-normalized-base-url` with two project workers, one original-IRIS label thread per project, `DeepSeek-V4-Pro`, four JSON-list transport attempts, and bridge capacity eight.

**Verification:**

- Commons IO and Hutool each entered copied original `src/iris.py`, completed their CodeQL candidate-extraction stages, and reached native API labelling.
- The first two bridge metric records are successful `completed` calls attributed to the a12 run IDs, one for Commons IO and one for Hutool. This establishes that the generic URL fix removed the a11 pre-handler 404 failure.
- TraeX did not report total token counts for these calls, so the corresponding metric fields remain `null`.
- a12 evidence root:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a12-normalized-base-url/`.

**Decision:** a12 is actively executing native IRIS and has passed the transport-start milestone only. It has not yet produced any verified result; completion accounting remains gated on original IRIS exit code, all required artifacts, and valid JSON-list responses for every dispatched label prompt.

**Next:** Monitor a12 until each receipt is written. Audit every completed receipt independently, then update coverage only with `completed_verified` rows; Vert.x will begin after one of the two bounded project workers becomes available.

### Round 16 - Generic Compile Builder Action Validation and DB Coverage Extension

**Goal:** Remove controller-level incompatibilities that prevented a bounded LLM repair proposal from reaching a valid Maven/CodeQL build, while preserving the frozen 45-case native-IRIS boundary and the strict downstream completion gate.

**Scope:** The frozen Compile Builder repair input admits exactly four rows whose only remaining native-IRIS prerequisite is a missing CodeQL database: Axis `CVE-2023-51441`, Tika `CVE-2018-11762`, Keycloak `CVE-2022-4361`, and Spring Cloud Config `CVE-2020-5405`. Tika already has a completed database and verified native-IRIS result. This round uses no source edits, source-revision substitutions, query changes, or case-specific build recipes.

**Action:**

- Audited the OpenAI-compatible bridge output from the generic Compile Builder v2 dispatcher. The model returned action objects with a generic `value` field, including approved Java/Maven homes and repeated build-argument actions, while the local validator expected only action-specific fields.
- Generalized the local validator to normalize those bridge action shapes only after approved-environment and build-argument allow-list validation. Conflicting or unapproved values continue to be rejected locally.
- Added one bounded, tool-less model correction round when a proposal fails local validation. The correction receives the validation error and must submit another fully allowed decision; source and query changes remain forbidden.
- Removed Gradle-only `--no-daemon` and `--stacktrace` from the global Maven-safe build-argument allow-list. The previous broad list let a legal-looking generic action append these options to an Axis Maven invocation, where Maven rejected them before compilation.
- Added regression coverage that verifies both Gradle-only options are rejected. The complete remote Compile Builder suite passed with `77 passed` before the focused commit; the local checkout lacks `pytest`, so the focused local command was unavailable.
- Pushed the final controller correction as `a4a3be9` (`Reject Gradle-only repair arguments`) on `bad-case`; the deployed remote package was synchronized to that version.
- Preserved the prior a5 Axis failure as evidence rather than rewriting it. a5 Keycloak and Spring CodeQL attempts continue in their original isolated attempt directories. A fresh a6 Axis invocation is scheduled through the same generic dispatcher only after a5 releases its two build slots, with one worker and the corrected general validator.

**Verification:**

- a5 records its original action, command, validator input, and database-create log. Axis is explicitly non-valid because Maven rejected the two Gradle flags; it is not represented as a source or IRIS failure.
- At the time of this update, Keycloak is actively resolving/building under approved Maven `3.9.9`; Spring Cloud Config has progressed through Maven modules under its original bounded CodeQL attempt. Neither database is counted until it contains both `codeql-database.yml` and `db-java`, and the Compile Builder receipt records `database_valid: true`.
- a12 remains an independent native-IRIS lane: Commons IO and Hutool are still executing copied original `src/iris.py` with real `DeepSeek-V4-Pro` bridge completions. Their intermediate outputs are not yet counted; all cases remain subject to the original return-code, artifact, and prompt-mapped JSON-list gates.

**Decision:** The controller now distinguishes safe generic repair decisions from build-tool-specific options. Database-building evidence, native-IRIS evidence, and failed historical attempts remain separate receipts. No new verified native-IRIS outcome is claimed in this round.

**Next:** Let a5 settle, validate any complete Keycloak/Spring database, run original native IRIS only for a newly valid complete DB with official IRIS inputs, then audit a12/a6 receipts and merge only `completed_verified` outcomes into the coverage ledger.

### Round 17 - Repaired-DB Native IRIS Admission

**Goal:** Admit only newly complete, exact-source CodeQL databases produced by the constrained Compile Builder v2 lane into a fresh native-IRIS execution boundary.

**Scope:** The four DB-only repair candidates remain fixed. Tika was already complete before this round. a5 completed Keycloak and a6 completed Axis; Spring remains a failed repair because its Maven Checkstyle configuration could not retrieve a remote suppression file. The old a5 Axis attempt is retained as a controller-failure receipt and is not reused.

**Action:**

- a5 completed Keycloak as `codeql_db_repaired` using the locally approved Maven `3.9.9` selection. Its database creation exited `0` and the resulting directory contains both `codeql-database.yml` and `db-java`.
- After a5 released its build slots, the scheduled a6 invocation reran only Axis through the same generic LLM dispatcher and corrected Maven-safe validator. The model selected approved Java 8 plus the allow-listed `-Dmaven.javadoc.skip=true` and `-Dmaven.source.skip=true` build options; CodeQL database creation exited `0` with a complete database layout.
- Constructed a two-row derived manifest from the frozen 45-row manifest. The only changed input for Axis and Keycloak is `input_paths.codeql_db`; each row records the producing repair ledger, validated decision hash, exact-source evidence, database path, and a derived-manifest hash.
- Independently revalidated the derived rows against the original 143-case allowlist, official IRIS identity admission, source/package paths, and full CodeQL layout before starting any model call.
- Launched fresh native attempt `qa-iris-v2-45-a13-repaired-db` for the two rows using copied original `src/iris.py`, `DeepSeek-V4-Pro`, two project workers, one original-IRIS label thread per project, and bridge capacity eight.

**Verification:**

- Derived manifest SHA-256:
  `140355f47be83b23303890682968190b12348d42fb1d2ef64d60f9cafad5d724`.
- Binding receipt:
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/repro/qa-iris-v2-45-a1/results-a13-repaired-db-native-iris/a13-db-binding-receipt.json`.
- Both derived rows passed the native batch's path and full-CodeQL preflight before dispatch.
- Axis and Keycloak both entered copied original `src/iris.py`; the local bridge recorded the first successful Axis completion. a12 remains active independently for Commons IO and Hutool.
- With a12 and a13 together, four projects each use one native label thread. The bridge semaphore remains the authoritative cap of eight actual model completions.

**Decision:** Compile Builder success is now a separately evidenced prerequisite that can feed native IRIS without overwriting the frozen evaluation manifest or silently reusing an invalid database. a13 is active execution only; no case is counted until its strict receipt records original IRIS success, every required artifact, and valid prompt-mapped JSON-list responses.

**Next:** Monitor a12 and a13 receipts to completion, independently audit all strict gates, and merge only `completed_verified` outcomes into the 45-case coverage ledger. Retain Spring as a constrained-repair failure until a future generic controller capability addresses its documented Maven quality-gate failure.

### Round 18 - Bounded Build-Feedback Replanning in Compile Builder v2

**Goal:** Close the general controller gap where a locally valid, bounded repair action could fail to create a CodeQL database but the dispatcher would terminate without allowing the model to inspect the new redacted build evidence.

**Scope:** This round changes the generic Compile Builder v2 controller only. It preserves the frozen 45-case manifest, exact source revision evidence, official IRIS inputs, and the existing model action allow-list. It introduces no source edits, revision substitutions, query changes, package installation, network configuration, or per-project build recipe.

**Action:**

- Added one bounded build-feedback replan round to `run_codeql_llm_repair_dispatch.py`. After a locally validated decision executes and returns `repair_attempt_failed`, the controller receives the completed attempt packet whose `failed_attempt.log` is refreshed from that attempt's final redacted `codeql-repair.log`.
- The controller sends that fresh packet to the same tool-less model interface and applies the same local validator before a second CodeQL creation attempt. The prompt includes the previous decision and requires a different action set rather than an unbounded retry.
- Stored every model call, proposal-validation error, validated decision, refreshed packet, and execution receipt under the original per-case attempt directory. The receipt records `repair_attempts`, the feedback replan count, and the explicit bounded-loop contract.
- Added a duplicate-decision guard. If the model proposes the same locally validated decision after a failed execution, the controller records `no_safe_llm_repair` and does not execute it a second time.
- Added regression coverage for both paths: a first failed attempt followed by a distinct feedback decision that succeeds, and a repeated feedback decision that is not re-executed.
- Added `prepend_maven_clean`, a generic constrained action available only when the recorded build command is a direct Maven lifecycle invocation. It inserts Maven's `clean` lifecycle before the existing lifecycle goal, removing generated build outputs to force compiler execution and CodeQL capture without modifying source files, revisions, or arbitrary command text.
- Clarified feedback-replan semantics: because every candidate is rebuilt from the original command, a replacement proposal must explicitly retain any earlier allow-listed action that is still necessary. This prevents a later environment action from silently dropping a required quality-gate skip.
- Added regression coverage for the direct-Maven-only clean action, rejection for non-Maven builds, model-schema availability, build-feedback replan, and duplicate-decision suppression. The full remote Compile Builder suite passed with `82 passed in 2.63s`. The local checkout has no `pytest`, but all changed Python files pass `py_compile`.
- Added a source-integrity gate around every new repair build. The controller hashes all non-generated source content before and after execution, while excluding only generic build-output/VCS directories (`target`, `build`, `out`, `.gradle`, `.git`). A complete CodeQL layout is rejected if any other source path changes. Regression coverage verifies that generated `target` output is allowed and a changed Java source file converts an otherwise valid database into `repair_attempt_failed`. The full remote suite passed with `84 passed in 2.60s`.
- Materialized an independent archive-verified source tree for every new repair execution round. The dispatcher checks the retained archive hash and revision-bound codeload URL, safely extracts one top-level source tree, rewrites only CodeQL's `--source-root` to that tree, and records the materialization receipt. This eliminates prior `target` outputs and any prior build-plugin side effects from later attempts while retaining the original exact-source archive as the identity root. The full remote suite passed with `85 passed in 2.64s`.
- The independent a8 Spring attempt exercised the first generic feedback loop and ended as `repair_attempt_failed`: its first decision appended quality-gate skips and reached Maven `BUILD SUCCESS` in 33 seconds, but CodeQL reported zero Java/Kotlin capture. Its fresh feedback packet was classified `codeql_no_source_capture`; the second, locally valid Java 17 plus `-Xmx4g` decision again reached Maven `BUILD SUCCESS` but CodeQL still reported zero capture and produced no Java relation files. a8 is retained as evidence only and does not create a usable database or native-IRIS admission.
- Started a fresh, evidence-preserving Spring Cloud Config repair invocation `a8` for `case::e182cf07540c8aa7fcc0`. It uses a new output namespace, the same four-case frozen repair input, approved Java/Maven homes, one worker, the reverse-tunneled `DeepSeek-V4-Pro` bridge, and a 5,400-second CodeQL bound. The old a5 receipt is retained unchanged.

**Verification:**

- Remote package and local checkout have matching dispatcher SHA-256 after deployment.
- The local Pro bridge and reverse SSH tunnel are live; the dispatcher entered its first constrained model-decision stage and wrote a new packet/prompt in the a8 attempt directory.
- The bridge-level semaphore remains the authoritative model-concurrency limit of eight. The a8 repair lane issues at most one model request at a time and shares that limit with the active native-IRIS runs.

**Decision:** Spring is no longer blocked by a controller limitation. Its a8 outcome remains pending and will be accepted only if a new CodeQL database creation exits successfully and produces the complete database layout. Any failed or rejected bounded decision remains a recorded non-success, not a source-level or native-IRIS result.

**Next:** Let a8 finish, audit its complete receipt and database layout, and admit Spring to a fresh copied-original native-IRIS run only if all existing official-input and exact-source gates still pass. Continue monitoring a12/a13 independently; no active execution is counted before its strict completion receipt is present.

## Near-Term Checklist

- [x] Recover historical M11 code and 49-case results.
- [x] Continue all healthy, preflight-eligible, previously unrun M11 cases with bounded concurrency.
- [x] Independently audit continuation TP cases.
- [x] Run one artifact-gated native IRIS + local TraeX smoke.
- [x] Enqueue the 63-case native-IRIS-ready Java cohort with `DeepSeek-V4-Pro` at two-way concurrency.
- [ ] Produce a 143-case v2 unified alignment ledger: M11 completed, CodeQL-only, native-IRIS, and out-of-scope.
- [ ] Complete and merge metrics for the native-IRIS-ready Java cohort.
- [ ] Freeze a train-only guideline release before HCVR ranking evaluation.
- [ ] Build TOCTOU functions/windows baseline and hard-negative corpus.
- [ ] Compare BM25, pretrained embedding, classifier, and K-prototype Recall@K.
