# Guideline Agent Pipeline

This module is the cleaned implementation of the simplified Route-Hacker flow:

```text
offline guideline clustering / guideline release
  -> online guideline-conditioned anchor recall
  -> per-anchor Codex harness audit
  -> audit report with risk/no-risk, confidence, and PoC handoff locations
  -> later PoC agent instrumentation and dynamic validation
```

The implementation keeps the boundary intentionally small. Retrieval proposes
anchors. The audit agent decides `risk` or `no-risk`. The PoC stage is a handoff
contract in the audit report, not a hidden reducer or schema-heavy verifier.

Current frozen 143-case result, using the same identity file for both sides:

| Budget | Qwen3-Embedding-4B | P3C64 query-residual | Delta |
| --- | ---: | ---: | ---: |
| Top-30 | 30/143 = 0.2098 | 45/143 = 0.3147 | +15 cases / +10.5 pp |
| Top-50 | 37/143 = 0.2587 | 56/143 = 0.3916 | +19 cases / +13.3 pp |
| Top-100 | 55/143 = 0.3846 | 73/143 = 0.5105 | +18 cases / +12.6 pp |
| Top-150 | 65/143 = 0.4545 | 83/143 = 0.5804 | +18 cases / +12.6 pp |
| Top-200 | 74/143 = 0.5175 | 84/143 = 0.5874 | +10 cases / +7.0 pp |

Use Top-100 or Top-150 when making a `>10 percentage-point` result claim. Use
Top-200 as `+10 additional recovered cases`, not as `+10 percentage points`.
The detailed bad-case note is
`results/p3c64-fixed143-paper-eval-20260820/bad_case_analysis.md`.

## Files

- `scripts/run_hcvr_case_anchor_audits.py`
  - Reads an HCVR QA receipt.
  - Selects cases from `added_identities`.
  - Builds retrieval guidelines from explicit case text, clustering sidecar
    overrides, CWE templates, or coarse HCVR type templates.
  - Consumes selected anchors from a recall run, or uses each case's existing
    `recall_anchors` for audit-only compatibility runs.
  - Materializes the exact source checkout in a read-only snapshot.
  - Runs one Codex audit per selected anchor.
  - Writes free-form reports plus `audit_index.jsonl` and `summary.json`.
- `scripts/recall_guideline_anchors.py`
  - Materializes the exact source checkout in a read-only snapshot.
  - Mechanically slices source files into overlapping candidate anchors.
  - Builds the case guideline from the QA receipt, with optional guideline
    sidecar overrides.
  - Ranks candidates by guideline-conditioned embedding similarity.
  - Supports `openai`, `sentence-transformers`, and the recovered
    `p3c64-query-residual` backend.
  - Uses known anchors only after ranking to compute Hit@K and MRR.
- `scripts/compare_recall_rank_tables.py`
  - Compares two recall rank tables by `identity_key`.
  - Fails by default when the identity sets differ, so model A/B runs do not
    accidentally compare different case subsets.
  - Supports explicit `--allow-mismatch` for intersection diagnostics.
- `scripts/merge_recall_shards.py`
  - Merges per-case recall output directories into a single
    `recall_results.jsonl`, `selected_cases.jsonl`, `summary.json`, and
    `README.md`.
  - Recomputes Hit@K and MRR from merged results.
  - Marks identity-file rows with missing shard outputs as missing cases.
- `scripts/evaluate_guideline_groups.py`
  - Evaluates the guideline release itself, independent of embedding recall.
  - Reports coverage, source-only groups, mixed HCVR/CWE sanity checks, and
    actionability fields.
  - Optionally emits a TraeX LLM-as-judge prompt pack for semantic mechanism
    review.
- `scripts/summarize_guideline_judge_outputs.py`
  - Summarizes TraeX/LLM judge outputs into decision counts, score averages,
    and prioritized guideline rows needing revision, splitting, merging, or
    more evidence.
- `scripts/derive_guideline_from_audit.py`
  - Converts a successful risk audit report into a generalized guideline track.
  - Emits both `guideline_tracks.yaml` and a cve_clustering-style guideline
    artifact.
- `scripts/extract_poc_handoff_from_audit.py`
  - Converts completed `risk` audit rows into PoC-agent handoff packets.
  - Extracts `file:line` candidates from the report body without claiming they
    are final proof.
- `tests/`
  - Unit tests for footer parsing, command-event validation, QA case selection,
    prompt construction, and deterministic guideline derivation.

## Audit Contract

Each audit report is plain text, but it must end with exactly two
machine-readable lines:

```text
Decision: risk
Confidence: 0.90
```

or:

```text
Decision: no-risk
Confidence: 0.75
```

`unknown` is not a valid decision.

For `risk`, the body should include:

- the anchor relation;
- exact `file:line` locations for the missing or incorrect security condition;
- exact `file:line` locations for the sensitive effect;
- runtime conditions, variables, branch predicates, and state that a later PoC
  agent should observe or instrument to eliminate false positives.

## Recall Guideline Anchors

Use this stage when evaluating the full online retrieval path:

```text
QA case guideline -> source snapshot -> mechanical candidate slices
  -> embedding recall Top-K -> selected audit anchors
```

P3C64 is the current recovered HCVR method with positive recall evidence. It
keeps candidate code vectors as frozen Qwen3-Embedding-0.6B vectors and adapts
only the query/guideline vector with a residual MLP.

Guideline construction is deliberately kept on the query side. The default
builder uses the case's explicit `guideline_text`, `retrieval_guideline`, or
`audit_guideline` when present, then falls back to CWE templates and coarse
HCVR type templates. It does not infer mechanism-specific queries from ad hoc
regular expressions over advisory text; mechanism names such as JNDI, LDAP,
RMI, unsafe template evaluation, or SSRF-through-JNDI must come from a
reviewable offline guideline release or from an explicit sidecar override.
Known anchors, ranks, file paths, and line numbers are never used to construct
the retrieval query.

## Guideline Clustering Roadmap

The intended offline-to-online contract is:

```text
CVE metadata + patch diff
  -> code-centric root-cause extraction
  -> cluster refinement into evidence neighborhoods and sub-patterns
  -> mechanism attribution inside each neighborhood
  -> one reusable guideline per cluster-scoped mechanism
  -> guideline sidecar consumed by recall and audit
```

The historical `cve_clustering` implementation already has the right artifact
shape: each structured CVE carries `root_cause`, `abstract_pattern`,
`data_flow`, `trigger_condition`, and `fix_strategy`; refined clusters can
carry `sub_patterns` with their own root cause, fix strategy, and member CVEs;
guideline generation expands broad clusters into reviewable mechanism-scoped
guidelines. When `--cases-file` is provided, the release also emits
`guideline_overrides.jsonl`, which recall and audit consume through
`--guideline-file`.

The current weakness is guideline granularity. Broad buckets such as `iris`,
`m9_wave2`, `m9_wave4`, and `m9_expansion` are useful for bookkeeping, but they
are too coarse as retrieval queries. A Java naming bug should surface as a
JNDI/LDAP/RMI lookup guideline, and an outbound lookup bug should be expressible
as SSRF through a naming or lookup API rather than as a generic SSRF or generic
security-relevant code path. This module now implements that split as an
offline release step, backed by a reviewable mechanism lexicon.

For the next guideline-v2 iteration:

1. Treat `bad-case` branch material as motivation and regression data,
   including the historical bad-case notes and the fixed-143 retrieval
   evidence.
2. Improve offline cluster refinement so `sub_patterns` are mechanism-level
   and audit-actionable, not umbrella vulnerability categories.
3. Emit a sidecar keyed by `identity_key` or `case_id` for this module to
   consume without mutating the dataset.
4. Rerun P3C64 on the frozen 143 identity file and compare against
   `results/p3c64-fixed143-paper-eval-20260820/` at Top-100, Top-150, and
   Top-200.

The current implementation does not abandon clustering. It changes the role of
clustering: clusters provide the local historical evidence neighborhood, while
mechanism attribution decides the released guideline boundary. A broad cluster
can therefore emit separate guidelines for JNDI lookup, webhook SSRF,
redirect-following SSRF, template evaluation, or pending-review mechanisms.

Generate a guideline-v2 preview from cve_clustering artifacts:

```bash
python new-impl/guideline-agent-pipeline/scripts/generate_mechanism_guidelines.py \
  --clusters /path/to/refined_clusters.json \
  --structured /path/to/structured_cves.jsonl \
  --output-dir /path/to/mechanism-guideline-release
```

The default `--group-scope cluster-mechanism` emits one guideline per
`(cluster_id, mechanism_id)`. This keeps JNDI-in-cluster-9 separate from
JNDI-in-cluster-11, while still preserving both the cluster context and the
human-readable mechanism label. Use `--group-scope mechanism` only for ablation
against the older global same-mechanism aggregation. Use
`--group-scope sub-pattern` when the refined cluster already contains high
quality sub-pattern boundaries and you want the narrowest release.

The mechanism lexicon is an offline release asset:

```text
guidelines/mechanism_lexicon.seed.json
```

It records reusable mechanism names, aliases, source shape, sink shape, missing
guard, and typical fix text. Unknown work items are written as
`pending_review`; the next lexicon iteration can be maintained manually or by an
LLM reviewer that proposes new entries from those pending rows. The online
recall runner consumes the released `guideline_overrides.jsonl` sidecar and
does not infer mechanism words from advisory regexes.
By default, `pending_review` guidelines stay in the release for human and
LLM-as-judge review but are excluded from `guideline_overrides.jsonl`, because
they are not yet stable retrieval queries. Use `--include-pending-overrides`
only for an explicit ablation that measures the cost of letting unresolved
guidelines enter recall.

Committed preview outputs:

- `results/mechanism-guideline-preview-smoke-cluster-scope-20260821/` shows a
  deliberately broad cluster split into separate JNDI and webhook SSRF
  guidelines.
- `results/mechanism-guideline-preview-v2-cluster-scope-20260821/` applies the
  same generator to the historical cve_clustering v2 artifacts. It emits 160
  guidelines from 303 work items: 231 active lexicon attributions and 72
  pending-review attributions.
- `results/guideline-v2-badcase12-regression-20260821/` records a same-identity
  regression over 12 old P3C64 Top-100 misses covered by the first guideline-v2
  sidecar. It improves Top-100 from 0/12 to 5/12, but 3 cases regress in rank.
- `results/mechanism-guideline-preview-v2-cluster-scope-r2-20260821/` is the
  next guideline-v2 preview. It gives sub-pattern evidence precedence over
  broad cluster summaries during mechanism attribution and adds narrower
  mechanisms for request-body resource mismatch authorization, temporary
  directory create-delete-mkdir TOCTOU, and privileged server-side capability
  exposure.
- `results/mechanism-guideline-preview-v2-cluster-scope-r3-20260821/` adds an
  explicit unsafe URI scheme open-redirect mechanism. This keeps redirect URI
  validation cases from falling into the broader webhook/SSRF bucket while
  preserving the r2 sub-pattern attribution changes.
- `results/guideline-v2-r3-badcase12-regression-20260821/` records the r3
  same-identity regression on the same 12 old P3C64 Top-100 misses. r3 reaches
  Top-100 5/12, Top-200 7/12, and Top-500 9/12. It is the best current
  single-guideline candidate, but it is not strong enough for hard replacement
  without a regression gate.
- Remote diagnostic run
  `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-guideline-v2-badcase30-20260821T0505/v2-r3-baseline-plus-override-covered12-gpu6-20260821T183746/`
  tested same-candidate max-score fusion between the baseline guideline and
  the r3 override. It kept Top-100 at 5/12 but dropped Top-200 to 6/12 and
  Top-500 to 8/12. Use this mode for diagnostics, not as the next default full
  143-case policy.

The r1/r2/r3 bad-case regressions are useful but not yet sufficient for a full
replacement run. Treat them as evidence that mechanism-scoped guidelines help
some old misses and that attribution quality still needs a regression gate or
offline list-level fusion policy before full paper-eval replacement.

## Guideline Quality Evaluation

Evaluate guideline generation on three separate axes:

```text
guideline release
  -> structural sanity check over joined unified-case metadata
  -> semantic LLM-as-judge review over grouped CVE evidence
  -> same-identity embedding recall evaluation
```

The structural checker is deliberately limited. It reports coverage,
source-only groups, small groups, mixed HCVR/CWE labels, and missing
actionability fields. These fields catch broad or incomplete guideline groups,
but they are not the definition of a good mechanism. A valid mechanism can cut
across multiple CWE labels, and a high-purity label bucket can still be too
generic to guide audit.
Do not tune the generator to satisfy these flags mechanically. Treat them as a
queue for semantic review, then decide from source/sink shape, missing guard,
exploit precondition, and safe fix evidence.

Run the structural checker and emit a TraeX judge pack:

```bash
python new-impl/guideline-agent-pipeline/scripts/evaluate_guideline_groups.py \
  --release-dir new-impl/guideline-agent-pipeline/results/mechanism-guideline-preview-v2-cluster-scope-r3-20260821 \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --output-dir new-impl/guideline-agent-pipeline/results/guideline-v2-r3-group-eval-20260823 \
  --judge-pack-dir new-impl/guideline-agent-pipeline/results/guideline-v2-r3-group-eval-20260823/llm_judge_pack \
  --judge-group-filter flagged \
  --judge-max-groups 20
```

Outputs:

```text
/path/to/group-eval/
  summary.json
  group_report.jsonl
  group_report.tsv
  case_assignments.jsonl
  README.md
  llm_judge_pack/
    judge_inputs.jsonl
    prompts/
    run_traex_judge.sh
```

The LLM judge prompt asks for JSON with `accept`, `revise`, `split`, `merge`,
or `needs_evidence`. The target is semantic guideline quality: whether the
group shares a reusable root-cause mechanism, whether the guideline names the
right source, sink, missing guard, and fix, and whether the text is a useful
retrieval/audit query. It does not judge embedding recall ranks.

Run the generated judge pack with TraeX:

```bash
cd new-impl/guideline-agent-pipeline/results/guideline-v2-r3-group-eval-20260823/llm_judge_pack
TRAE_JUDGE_TIMEOUT_SECONDS=1800 ./run_traex_judge.sh judge_outputs
```

Summarize the judge outputs after the run:

```bash
python ../../../scripts/summarize_guideline_judge_outputs.py \
  --judge-inputs judge_inputs.jsonl \
  --judge-output-dir judge_outputs \
  --output-dir judge_summary
```

This keeps the online recall path clean: no runtime regex fallback and no
hidden label-based routing. Judge output is advisory evidence for the next
guideline iteration; retrieval claims still require same-identity embedding
recall runs.

The r4 TraeX judge run over 20 flagged guideline groups is committed under
`results/guideline-v2-r4-group-eval-20260823/llm_judge_pack/judge_summary/`.
It parsed all 20 outputs with no missing or invalid files, but returned
`accept=0`, `revise=8`, `split=7`, and `needs_evidence=5`. The dominant
failures were mechanism/evidence mismatch, overly generic guideline wording,
and pending groups entering retrieval as if they were stable mechanisms. The
next generation policy is therefore:

1. Keep mechanism naming in offline release artifacts and sidecars; do not add
   online regex fallback or hidden label routing.
2. Let mechanism lexicon fields carry the specific guard semantics instead of
   appending a universal authorization/resource-binding sentence to every
   guideline.
3. Keep `pending_review` groups visible for semantic review, but exclude them
   from the default recall sidecar until the mechanism evidence is sufficient.

The r5 policy removes the universal resource/principal/destination/object
binding boilerplate and excludes `pending_review` guidelines from the default
recall sidecar. The generated release is committed under
`results/mechanism-guideline-preview-v2-cluster-scope-r5-20260823/`: 202
guidelines, 237 active attributions, 89 pending-review attributions, 153 recall
sidecar rows, and no pending-review sidecar rows by default. Its group eval is
under `results/guideline-v2-r5-group-eval-20260823/`: 68 groups join to unified
case metadata, 134 are source-only historical groups, weighted HCVR purity is
0.7568, and weighted CWE purity is 0.8676. The r5 TraeX judge run parsed all
20 outputs with no missing or invalid files and returned `accept=0`,
`revise=8`, `split=4`, `needs_evidence=8`, and low-score `18/20`. Treat this
as evidence that r5 cleaned the release policy but did not solve guideline
quality. The remaining high-priority issues are wrong mechanism attribution,
insufficient case evidence, and pending groups that still need specific
source/sink/guard wording before they become stable recall queries. Do not
optimize the generator toward fixed judge keywords or structural flags; use the
judge notes as reading order for the next evidence-driven mechanism split.

For model A/B evaluation, always pass the same `--identity-file` to every run.
`--selection all --limit N` without `--identity-file` selects the first N
accepted cases in `new_unified_cases.v1.jsonl`; that is useful for quick smoke
runs, but it is not interchangeable with the frozen paper-eval allowlist.

```bash
CUDA_VISIBLE_DEVICES=0 python new-impl/guideline-agent-pipeline/scripts/recall_guideline_anchors.py \
  --qa new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --identity-file /path/to/paper_eval_143_identities.jsonl \
  --guideline-file /path/to/guideline_overrides.jsonl \
  --guideline-mode baseline-plus-override \
  --output-dir /path/to/run/p3c64-recall30 \
  --repo-cache /path/to/run/repo-cache \
  --snapshot-root /path/to/run/snapshots \
  --selection all \
  --limit 30 \
  --top-k 200 \
  --audit-anchor-rank 1 \
  --case-workers 2 \
  --embedding-backend p3c64-query-residual \
  --embedding-model /data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B \
  --embedding-device cuda:0 \
  --embedding-batch-size 128 \
  --max-seq-length 512 \
  --p3c64-state /data/lhq/workspace/p3-hard-competition-query-adapter-v1/selection_run_v1/p3c64_state.pt
```

`--guideline-file` is optional. It accepts JSONL rows or a JSON object keyed by
`identity_key`, `new_unified_case_id`, or `case_id`; each row may contain
`guideline_text`, `retrieval_guideline`, `audit_guideline`, or `guideline`.
Use it to attach offline guideline-clustering output without mutating the
dataset. Recalled `selected_cases.jsonl` rows carry the exact guideline used by
retrieval so the audit stage can reuse the same text.

`--guideline-mode` defaults to `override`, which preserves the historical
single-query behavior: when `--guideline-file` is supplied, the released
sidecar guideline replaces the broad dataset/template guideline for that case.
Use `--guideline-mode baseline-plus-override` for regression-sensitive
experiments. In that mode the runner embeds both the original baseline
guideline and the released override guideline, scores every candidate by the
maximum similarity across the two query vectors, and records the winning
`query_label` plus per-query scores in `recall_results.jsonl`. A 12-case smoke
test showed that this same-score-space max operation is diagnostic but not a
good default fusion policy. Prefer separate baseline and override recall runs
followed by list-level RRF or candidate union when trying to preserve old hits
while adding mechanism-specific recoveries.

Outputs:

```text
/path/to/run/p3c64-recall30/
  recall_results.jsonl
  selected_cases.jsonl
  summary.json
  README.md
```

Compare a P3C64 run against a frozen baseline only after confirming both sides
used the same identities:

```bash
python new-impl/guideline-agent-pipeline/scripts/compare_recall_rank_tables.py \
  --left /path/to/p3c64/recall_results.jsonl \
  --right /path/to/qwen4b/case_rank_table.jsonl \
  --left-label p3c64-query-residual \
  --right-label qwen3-embedding-4b \
  --budgets 30,50,100,200,300,500 \
  --primary-budget 200 \
  --output-json /path/to/comparison/summary.json \
  --output-md /path/to/comparison/README.md
```

If the command fails with `identity sets differ`, rerun the inconsistent side
with the frozen identity file. Use `--allow-mismatch` only when intentionally
debugging the overlapping subset.

For sharded per-case runs, merge outputs before comparing:

```bash
python new-impl/guideline-agent-pipeline/scripts/merge_recall_shards.py \
  --shard-root /path/to/run/output \
  --output-dir /path/to/run/merged \
  --identity-file /path/to/paper_eval_143_identities.jsonl \
  --budgets 30,50,100,200,300,500
```

When two same-identity recall runs have full `top_anchors`, fuse their anchor
rankings with reciprocal rank fusion (RRF). This is useful when a tuned query
adapter and a larger base embedding model recover complementary known anchors:

```bash
python new-impl/guideline-agent-pipeline/scripts/fuse_recall_rank_tables.py \
  --left /path/to/p3c64/recall_results.jsonl \
  --right /path/to/qwen4b/merged_recall_results.jsonl \
  --left-label p3c64-query-residual \
  --right-label qwen3-embedding-4b \
  --left-weight 1.5 \
  --right-weight 1.0 \
  --rrf-k 60 \
  --per-source-cap 1000 \
  --budgets 30,50,100,200,300,500 \
  --output-dir /path/to/fused-rrf
```

The fusion script intentionally requires both inputs to have the same identity
set and order. It outputs another recall-compatible `recall_results.jsonl`, so
the fused result can be compared with `compare_recall_rank_tables.py` or fed to
the audit stage through its generated `selected_cases.jsonl`.

Feed `selected_cases.jsonl` to the audit runner with `--selected-anchor-file`
when you want the next stage to audit recalled anchors instead of
dataset-provided anchors.

```bash
python new-impl/guideline-agent-pipeline/scripts/run_hcvr_case_anchor_audits.py \
  --qa new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --selected-anchor-file /path/to/run/p3c64-recall30/selected_cases.jsonl \
  --guideline-file /path/to/guideline_overrides.jsonl \
  --output-dir /path/to/run/audit-recalled30 \
  --repo-cache /path/to/run/repo-cache \
  --snapshot-root /path/to/run/snapshots \
  --codex-home ~/.codex \
  --temp-root /path/to/tmp \
  --selection all \
  --limit 30 \
  --concurrency 1 \
  --timeout 1200 \
  --max-attempts 1
```

## Prepare 20 QA Cases

This prepares packets without calling Codex:

```bash
python new-impl/guideline-agent-pipeline/scripts/run_hcvr_case_anchor_audits.py \
  --qa /path/to/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --output-dir /path/to/run/prepared20 \
  --repo-cache /path/to/run/repo-cache \
  --snapshot-root /path/to/run/snapshots \
  --codex-home ~/.codex \
  --temp-root /path/to/tmp \
  --limit 20 \
  --prepare-only
```

Use `--no-materialize` with `--prepare-only` when you only want prompt packets
and do not want to clone repositories yet.

## Run Codex Harness Audits

The default model is `qwen3-coder:30b`, matching the successful OpenMeetings
pilot harness.

```bash
python new-impl/guideline-agent-pipeline/scripts/run_hcvr_case_anchor_audits.py \
  --qa /path/to/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --output-dir /path/to/run/audit20 \
  --repo-cache /path/to/run/repo-cache \
  --snapshot-root /path/to/run/snapshots \
  --codex-home ~/.codex \
  --temp-root /path/to/tmp \
  --limit 20 \
  --concurrency 1 \
  --timeout 900 \
  --max-attempts 1
```

Outputs:

```text
/path/to/run/audit20/
  selected_cases.jsonl
  audit_index.jsonl
  summary.json
  reports/
    <case>.prompt.txt
    <case>.attempt-01.events.jsonl
    <case>.attempt-01.md
    <case>.events.jsonl
    <case>.md
```

The runner starts Codex in its own process group. If a timeout fires, it kills
the full process group so native Codex children do not remain orphaned.

## Seed a New Guideline from a Risk Audit

```bash
python new-impl/guideline-agent-pipeline/scripts/derive_guideline_from_audit.py \
  --audit-report /path/to/reports/rank-0020.md \
  --output-dir /path/to/derived-guideline \
  --track-id object_scoped_authorization_after_interface_permission
```

The derived guideline intentionally excludes project names, file names,
function names, and line numbers from the released guideline text.

## PoC Handoff

The PoC agent is downstream of this module. It should consume risk reports and
use the report body to choose instrumentation points. This module does not run
dynamic PoCs itself.

Recommended handoff fields are already present in the report text:

- anchor `file:line`;
- missing or incorrect condition `file:line`;
- sensitive effect `file:line`;
- branch predicates and variables to observe;
- expected runtime state that distinguishes true risk from false positive.

Build handoff packets from completed audit results:

```bash
python new-impl/guideline-agent-pipeline/scripts/extract_poc_handoff_from_audit.py \
  --audit-index /path/to/run/audit20/audit_index.jsonl \
  --output /path/to/run/audit20/poc_handoff.jsonl
```

## Test

```bash
python -m pytest -q new-impl/guideline-agent-pipeline/tests
```

## Operational Notes

- Keep run outputs outside the repository.
- Do not commit cloned repositories, snapshots, Codex logs, prompts from private
  code, credentials, or auth state.
- Use the QA receipt and source snapshots as inputs, not training data or
  hidden truth during audit.
