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

Committed preview outputs:

- `results/mechanism-guideline-preview-smoke-cluster-scope-20260821/` shows a
  deliberately broad cluster split into separate JNDI and webhook SSRF
  guidelines.
- `results/mechanism-guideline-preview-v2-cluster-scope-20260821/` applies the
  same generator to the historical cve_clustering v2 artifacts. It emits 160
  guidelines from 303 work items: 231 active lexicon attributions and 72
  pending-review attributions.

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
