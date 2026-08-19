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
