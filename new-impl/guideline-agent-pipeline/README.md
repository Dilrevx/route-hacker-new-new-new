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

Latest r7 guideline-sidecar rerun on the same 143 identities is stored in
`results/guideline-v2-r7-full143-p3c64-20260823/`. This run keeps the same
P3C64 query-residual backend and source snapshots, changes only the released
guideline sidecar, and gives a conservative full143 improvement over the old
P3C64 baseline: `+2` cases at Top-30, `+3` at Top-100, `+3` at Top-200, and
`+3` at Top-500. Use this as guideline-generation evidence, not as the
P3C64-vs-Qwen4B model-improvement claim.

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
- `scripts/build_guideline_revision_backlog.py`
  - Joins judge output with recall-alignment diagnostics into a guideline
    revision backlog.
  - Produces a review artifact only: it does not update released guidelines,
    change ranking, or add fallback rules.
- `scripts/build_guideline_evidence_worklist.py`
  - Converts a revision backlog plus grouped case evidence into a concrete
    source/sink/guard/fix collection queue.
  - Produces a review artifact only: it does not update released guidelines,
    lexicon entries, sidecars, ranking, or audit prompts.
- `scripts/build_guideline_boundary_repair_pack.py`
  - Extracts split/revise rows from the evidence worklist into a mechanism
    boundary repair pack with strong and weak example buckets.
  - Produces a review artifact only: it does not update released guidelines,
    lexicon entries, sidecars, ranking, or audit prompts.
- `scripts/build_guideline_case_review_packets.py`
  - Renders one Markdown source-evidence review packet per boundary repair
    item, with candidate boundaries, strong/weak examples, and blank evidence
    fields for reviewer completion.
  - Produces review handoff material only: unfilled packets are not
    release-ready guideline changes.
- `scripts/verify_guideline_review_ledger.py`
  - Validates filled reviewer ledger rows before any boundary can be promoted
    into a mechanism lexicon or guideline sidecar.
  - Requires source/sink/missing-guard/exploit-precondition/fix evidence for
    `promote_boundary` rows and still does not edit released artifacts.
- `scripts/audit_guideline_dual_axis_objective.py`
  - Audits the current guideline iteration against the two coupled goals:
    semantic CVE-mechanism guideline quality and tuned-embedding recall
    compatibility.
  - Produces a completion-gate artifact only: it does not change generation,
    recall, ranking, or paper result tables.
- `scripts/propose_mechanism_lexicon_updates.py`
  - Converts a revision backlog into review-only candidate lexicon updates and
    recall investigation tasks.
  - Proposed text is never consumed by recall until it is manually promoted into
    a versioned lexicon and rerun through same-identity evaluation.
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
Lexicon entries may also declare `required_keywords`, a list of evidence groups
where each group is a string or a list of alternative strings. This is an
offline attribution constraint: a mechanism participates only when every group
has at least one phrase present in the CVE evidence text. Use it to prevent
generic terms such as `filter`, `escape`, or `length` from pulling unrelated
clusters into LDAP, SQL, or binary-length mechanisms. Do not use it as an
online source-code scanner or as a hidden case-specific fallback.
By default, `pending_review` work items are not written into `guidelines/`,
`index.json`, or `guideline_overrides.jsonl`. They remain visible in
`mechanism_candidates.jsonl` and `review_queue.jsonl` for human and
TraeX LLM-as-judge review, because they are not yet stable retrieval queries.
Use `--include-pending-guidelines` only when building a review ablation that
needs pending rows inside `index.json`; use `--include-pending-overrides` only
for an explicit ablation that measures the cost of letting unresolved
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
- `results/mechanism-guideline-preview-v2-cluster-scope-r5-combined-baseline-20260823/`
  is a same-input seed-only baseline for the combined 97-cluster input. It is
  used only to compare r6 candidate lexicon behavior against the same source
  artifacts.
- `results/mechanism-guideline-preview-v2-cluster-scope-r6-candidate-20260823/`
  adds `guidelines/mechanism_lexicon.candidate_r6.json` through
  `--extra-lexicon`. The candidate lexicon introduces review-only mechanism
  entries for LDAP filter injection, HTML sanitizer policy gaps, binary
  length/resource bounds, authentication artifact validation, dynamic SQL
  fragments, inline Content-Disposition XSS, temporary-resource permissions,
  and archive symlink extraction escape.

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

The guideline objective has two coupled but separate requirements:

- **Semantic classification quality**: guidelines should describe reusable CVE
  mechanisms that are general enough to transfer across projects and specific
  enough to direct an audit. Evaluate this with source evidence, structural
  sanity checks, and human or TraeX LLM-as-judge review.
- **Embedding recall compatibility**: those guidelines should also work as
  queries for a frozen candidate-slicing and embedding backend. Evaluate this
  only with same-identity recall A/B runs.

Bad recall cases are valid motivation for the next guideline iteration, but
they are not answer keys. If a guideline group is semantically coherent and its
source/sink/guard evidence is strong, a miss should first trigger recall-side
debugging: query wording, candidate slicing, embedding backend, Top-K budget,
or list-level fusion. Do not degrade the guideline taxonomy solely to satisfy a
single embedding model, and do not introduce hidden regex routing or per-case
fixes.

TraeX LLM-as-a-judge belongs on the semantic-classification side of this split.
Its rubric should ask whether a guideline names a reusable mechanism with
coherent source, sink, missing guard, exploit precondition, and fix semantics.
It should not score embedding rank, known-anchor hit, or Top-K recall, and its
output should create review/backlog items rather than silently changing the
released guideline set.
In practice the promotion chain is: structural sanity creates a review queue,
TraeX judge gives an advisory second opinion, source-reviewed ledger rows record
the boundary decision, and same-identity recall runs measure retrieval impact.
Do not collapse those layers into one score.

Run the structural checker and emit a TraeX judge pack:

```bash
python new-impl/guideline-agent-pipeline/scripts/evaluate_guideline_groups.py \
  --release-dir new-impl/guideline-agent-pipeline/results/mechanism-guideline-preview-v2-cluster-scope-r3-20260821 \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --output-dir new-impl/guideline-agent-pipeline/results/guideline-v2-r3-group-eval-20260823 \
  --judge-pack-dir new-impl/guideline-agent-pipeline/results/guideline-v2-r3-group-eval-20260823/llm_judge_pack \
  --judge-rubric new-impl/guideline-agent-pipeline/guidelines/judge_rubric.v1.md \
  --include-review-queue \
  --judge-group-filter balanced \
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

Without `--include-review-queue`, the structural report evaluates only released
guidelines in `index.json`. Add `--include-review-queue` when the purpose is
semantic triage and TraeX should also review withheld pending candidates.

The LLM judge prompt asks for JSON with `accept`, `revise`, `split`, `merge`,
or `needs_evidence`. The target is semantic guideline quality: whether the
group shares a reusable root-cause mechanism, whether the guideline names the
right source, sink, missing guard, and fix, and whether the text is a useful
retrieval/audit query. It does not judge embedding recall ranks.
The rubric lives in `guidelines/judge_rubric.v1.md`; update and version that
file when the semantic review standard changes, rather than burying new scoring
criteria inside the generator.
The recommended `balanced` judge filter samples evidence-limited groups,
label-mixed groups, clean controls, small groups, and source-only groups in
round-robin order. This keeps judge review from becoming a hardcoded
bad-case/label-purity test while still surfacing the groups most likely to need
human attention.

Run the generated judge pack with TraeX:

```bash
cd new-impl/guideline-agent-pipeline/results/guideline-v2-r3-group-eval-20260823/llm_judge_pack
TRAE_JUDGE_TIMEOUT_SECONDS=1800 ./run_traex_judge.sh judge_outputs
```

Summarize the judge outputs after the run:

```bash
python3 ../../../scripts/summarize_guideline_judge_outputs.py \
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

The r6 candidate iteration keeps the same generator policy and loads a separate
candidate lexicon file instead of overwriting the seed lexicon:

```bash
python new-impl/guideline-agent-pipeline/scripts/generate_mechanism_guidelines.py \
  --clusters .tmp/guideline_inputs/refined_clusters_combined.json \
  --structured .tmp/guideline_inputs/structured_cves_combined.jsonl \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --lexicon new-impl/guideline-agent-pipeline/guidelines/mechanism_lexicon.seed.json \
  --extra-lexicon new-impl/guideline-agent-pipeline/guidelines/mechanism_lexicon.candidate_r6.json \
  --output-dir new-impl/guideline-agent-pipeline/results/mechanism-guideline-preview-v2-cluster-scope-r6-candidate-20260823
```

On the same combined input, r6 candidate reduces pending attributions from 212
to 148 and increases recall sidecar rows from 232 to 252. The structural purity
stays effectively flat against the seed-only combined baseline: weighted HCVR
purity `0.8297 -> 0.8297`, weighted CWE purity `0.9179 -> 0.9142`, mixed HCVR
groups `8 -> 10`, and mixed CWE groups stays `7 -> 7`. Interpret this as a
coverage-expansion candidate that needs TraeX judge review and a same-identity
recall rerun before any paper-facing recall claim.

The r6 TraeX judge run confirms that coverage expansion alone is not enough:
20/20 judge outputs parsed, with `accept=0`, `split=8`, `revise=4`,
`needs_evidence=8`, and low-score `17/20`. The recurring failure mode is that
cluster or sub-pattern text can over-attribute a member to a mechanism even
when that member's own structured CVE evidence lacks enough source, sink,
missing-guard, or fix support.

The r7 evidence-gated iteration keeps the r6 candidate lexicon but requires
member-level structured evidence to support a mechanism before the member can
enter an active guideline. The gate is generic: it compares the member CVE text
against the mechanism's source shape, sink shape, missing guard, and typical
fix fields; it does not use CVE IDs, dataset labels, known anchors, or
judge-output keywords. If the highest-scoring mechanism lacks member evidence,
the generator tries the next mechanism; if none is supported, the member becomes
`pending_review`.

On the same combined input, r7 emits 563 guidelines from 746 work items, with
360 active attributions, 386 pending-review attributions, and 189 recall
sidecar rows. Structural quality improves relative to r6 candidate: weighted
HCVR purity `0.8297 -> 0.8659`, weighted CWE purity `0.9142 -> 0.9245`, and
mixed HCVR groups `10 -> 8`. The r7 TraeX judge run parsed 20/20 outputs with
`accept=1`, `split=3`, `revise=4`, `needs_evidence=12`, and low-score `17/20`.
This is a quality-control improvement, not a recall improvement claim: it
reduces wrong-mechanism mixing and surfaces thin evidence as pending work, while
showing that the next bottleneck is still source/sink/guard evidence collection
and specific wording for pending groups.

The next generator policy tightens the release boundary: only `release_ready`
guidelines enter `guidelines/`, `index.json`, and the recall sidecar by default.
Rows with unresolved mechanism evidence are written to `review_queue.jsonl`
instead. This keeps TraeX LLM-as-judge focused on semantic review material
without letting low-evidence candidates silently become retrieval queries.

The r8 release-ready run applies that boundary on the same combined input:
`results/mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/`
contains 177 released guidelines, 386 review-queue rows, 746 total mechanism
candidate rows, and 189 recall sidecar rows. The released-only structural eval
is under
`results/guideline-v2-r8-release-ready-released-only-eval-20260823/`: 177
released guidelines, 56 groups joined to unified case metadata, weighted HCVR
purity 0.8307, and weighted CWE purity 0.9171. The review-inclusive semantic
triage eval is under
`results/guideline-v2-r8-release-ready-group-eval-20260823/`: it sees the same
563 reviewable rows as r7, marks 386 as `review_only`, and emits a balanced
20-item TraeX judge pack with 4 evidence-limited, 4 label-mixed, 4 clean
control, 4 small-group, and 4 source-only examples. Treat this as a release
hygiene improvement; recall numbers remain the previously recorded full143 r7
P3C64 same-identity result until a fresh r8 recall run is executed.

The r8 TraeX judge run is committed under
`results/guideline-v2-r8-release-ready-group-eval-20260823/llm_judge_pack/`.
It parsed all 20 outputs with no missing or invalid files and returned
`accept=2`, `revise=5`, `split=3`, `needs_evidence=10`, and low-score
`14/20`. The judge-only revision backlog is under
`llm_judge_pack/revision_backlog_judge_only/`. Its recommended actions are:
10 `collect_source_sink_guard_evidence`, 5
`revise_mechanism_text_from_evidence`, 3 `split_mechanism_boundary`, and 2
`keep_as_control_group`. This is semantic review evidence only. It shows that
the release boundary is cleaner, while the next guideline-generation bottleneck
is still member-level source/sink/guard evidence and mechanism boundary
precision, especially for broad SSRF, XML, temporary-resource, authorization,
and template/expression groups.
The follow-up evidence collection worklist is committed under
`results/guideline-v2-r8-evidence-worklist-20260823/`. It keeps the same
review-only boundary and turns the judge backlog into concrete reviewer work:
20 rows, 15 rows needing source-level trace evidence, 10 rows needing explicit
source/sink/missing-guard/fix collection, 5 rows needing mechanism-scope
revision from checked evidence, 3 rows needing split-boundary validation, and
2 accepted control groups. Its case evidence states are 24
`source_trace_present`, 56 `review_entry_only`, and 8
`missing_trace_evidence`, which is why the next step is evidence collection
rather than direct guideline rewriting.
The split/revise subset is extracted under
`results/guideline-v2-r8-boundary-repair-pack-20260823/`: 8 repair rows, with
3 split-boundary items and 5 mechanism-scope revision items. It separates
strong source-trace examples from weak `review_entry_only` or missing-trace
examples so the next reviewer can assign cases to mechanism boundaries before
anything is promoted into the lexicon or recall sidecar.
The reviewer-facing packet set is committed under
`results/guideline-v2-r8-case-review-packets-20260823/`: 8 Markdown packets,
one per split/revise item. Each packet has candidate boundaries, source-trace
examples, weak examples, missing-trace examples, and blank reviewer fields for
source shape, sink or sensitive effect, missing guard, exploit precondition,
safe fix semantics, boundary decision, and recall follow-up.
The review ledger template is
`guidelines/guideline_review_ledger.template.jsonl`; the template validation
artifact is
`results/guideline-review-ledger-template-validation-20260823/`. The template
contains no promotable row by default. A later filled ledger must pass the
verifier before any boundary is promoted into released guideline text, and
promotion still triggers a fresh same-identity recall run once the consumed
sidecar changes.
The first filled r8 ledger row is
`guidelines/guideline_review_ledger.r8.gl_mech_0001.jsonl`, with validation
under `results/guideline-review-ledger-r8-gl-mech-0001-validation-20260823/`.
It promotes only `candidate_boundary_01`, the Java `File.createTempFile` ->
`delete` -> `mkdir/mkdirs` temporary-directory race, using source/patch-backed
evidence from CVE-2022-4817, CVE-2018-25068, and CVE-2022-3969. It explicitly
keeps temporary-resource permission exposure as a separate boundary candidate.
This is semantic boundary evidence, not a recall result.

The r8 experiment scorecard is committed under
`results/guideline-v2-r8-release-ready-scorecard-20260823/`. It records the
same release and judge evidence, plus the sidecar-equivalence check under
`results/guideline-v2-r8-vs-r7-sidecar-equivalence-20260823/`. The r8 sidecar
file hash differs from r7, but the actual `identity_key -> guideline text`
mapping consumed by recall is identical: 189 shared keys and 0 changed
consumed texts. Therefore the scorecard marks recall evidence as
`inherited_same_identity_by_sidecar_equivalence`: r8 inherits the already
measured r7 same-identity P3C64 recall table under unchanged identity file,
snapshots, slicing, embedding backend, adapter weights, and ranking parameters.
This is not a fresh r8 recall run. A fresh same-identity recall A/B is still
required if any consumed sidecar text, identity set, source snapshot, slicing
logic, embedding service, adapter state, or ranking parameter changes.

The current objective-level completion audit is
`results/guideline-v2-r8-objective-audit-20260823/`. It maps the active
requirements to concrete artifacts and marks the remaining gaps: r8 is a
cleaner, recall-compatible release boundary, but the semantic judge sample and
recall deltas do not yet justify calling the guideline-generation problem
solved.
The stricter dual-axis completion audit is
`results/guideline-v2-r8-dual-axis-objective-audit-20260823/`. It checks the
active objective against the current scorecard and evidence worklist. Its
status is `not_complete`: semantic guideline classification is
`partially_satisfied_needs_evidence`, and embedding recall is
`compatible_but_improvement_below_target`. The audit also records the required
next gates: source/sink/guard/fix evidence before changing guideline text,
fresh same-identity recall after sidecar text changes, taxonomy-vs-embed triage
for clean groups that still miss Top-K, and separated paper claim boundaries
for semantic quality, recall deltas, sidecar equivalence, and any engineering
fusion.

Build a cautious experiment scorecard when reporting a guideline iteration:

```bash
python new-impl/guideline-agent-pipeline/scripts/summarize_guideline_experiment.py \
  --release-summary new-impl/guideline-agent-pipeline/results/mechanism-guideline-preview-v2-cluster-scope-r5-20260823/summary.json \
  --group-summary new-impl/guideline-agent-pipeline/results/guideline-v2-r5-group-eval-20260823/summary.json \
  --judge-summary new-impl/guideline-agent-pipeline/results/guideline-v2-r5-group-eval-20260823/llm_judge_pack/judge_summary/summary.json \
  --release-label guideline-v2-r5 \
  --output-json /path/to/scorecard.json \
  --output-md /path/to/README.md
```

Add `--recall-comparison /path/to/same_identity_comparison.json` only when the
new guideline release has been evaluated against a baseline on the same frozen
identity file. Without that input, the scorecard deliberately reports recall
evidence as missing. If the comparison says the identity sets differ, the
scorecard marks the recall evidence invalid for paper-facing claims. This keeps
three facts separate:

- structural sanity describes whether the guideline release is internally
  reviewable;
- TraeX LLM-as-judge describes semantic mechanism quality and review priority;
- same-identity recall A/B describes one embedding plus guideline/query
  configuration.

Use the scorecard as the handoff artifact for paper discussion. It is not part
of online retrieval, does not call a model, and must not be used to introduce
keyword routing or hidden per-case fixes.

When a release changes only review metadata or release boundary files but keeps
the recall-consumed sidecar text unchanged, generate an explicit equivalence
artifact instead of rerunning a full 143-case recall job:

```bash
python new-impl/guideline-agent-pipeline/scripts/compare_guideline_sidecars.py \
  --left /path/to/measured-release/guideline_overrides.jsonl \
  --right /path/to/current-release/guideline_overrides.jsonl \
  --left-label measured-sidecar \
  --right-label current-sidecar \
  --output-json /path/to/sidecar-equivalence/summary.json \
  --output-md /path/to/sidecar-equivalence/README.md
```

Then pass both the measured same-identity recall comparison and the equivalence
summary into the scorecard:

```bash
python new-impl/guideline-agent-pipeline/scripts/summarize_guideline_experiment.py \
  --release-summary /path/to/current-release/summary.json \
  --group-summary /path/to/current-group-eval/summary.json \
  --judge-summary /path/to/current-judge-summary/summary.json \
  --recall-comparison /path/to/measured-same-identity-recall-comparison.json \
  --recall-equivalence /path/to/sidecar-equivalence/summary.json \
  --release-label current-release \
  --output-json /path/to/scorecard.json \
  --output-md /path/to/README.md
```

Only use this inheritance path when `recall_consumed_text_equivalent=true` and
the measured recall comparison itself has `same_identity_set=true`. It proves
query-side equivalence for the recall runner; it does not prove semantic
guideline quality and does not replace TraeX/human review.

To inspect whether bad cases look like guideline-quality failures or
embedding/candidate-recall failures, join a guideline group report with a recall
rank table:

```bash
python new-impl/guideline-agent-pipeline/scripts/diagnose_guideline_recall_alignment.py \
  --group-report new-impl/guideline-agent-pipeline/results/guideline-v2-r5-group-eval-20260823/group_report.jsonl \
  --case-assignments new-impl/guideline-agent-pipeline/results/guideline-v2-r5-group-eval-20260823/case_assignments.jsonl \
  --recall-results new-impl/guideline-agent-pipeline/results/p3c64-fixed143-paper-eval-20260820/p3c64_case_rank_table.jsonl \
  --recall-label p3c64-current-guideline-baseline-control \
  --baseline-results new-impl/guideline-agent-pipeline/results/p3c64-fixed143-paper-eval-20260820/qwen4b_case_rank_table.jsonl \
  --baseline-label qwen3-embedding-4b \
  --primary-budget 100 \
  --output-dir /path/to/guideline-recall-alignment
```

Read the alignment report as a diagnosis, not as a guideline-v2 recall result,
unless the recall table was generated with the same guideline sidecar being
evaluated. A clean guideline group with weak recall points toward embedding,
candidate slicing, or query wording; a mixed or pending group should be fixed
as guideline evidence before blaming the embedder.

Build a revision backlog from the semantic judge and recall-alignment outputs:

```bash
python new-impl/guideline-agent-pipeline/scripts/build_guideline_revision_backlog.py \
  --judge-summary new-impl/guideline-agent-pipeline/results/guideline-v2-r5-group-eval-20260823/llm_judge_pack/judge_summary/summary.json \
  --judge-report new-impl/guideline-agent-pipeline/results/guideline-v2-r5-group-eval-20260823/llm_judge_pack/judge_summary/judge_report.jsonl \
  --alignment-summary new-impl/guideline-agent-pipeline/results/guideline-v2-r5-recall-alignment-20260823/summary.json \
  --alignment-report new-impl/guideline-agent-pipeline/results/guideline-v2-r5-recall-alignment-20260823/group_recall_alignment.jsonl \
  --output-dir /path/to/guideline-revision-backlog
```

The backlog separates review actions including:

- `split_mechanism_boundary` for groups whose CVE evidence mixes reusable
  mechanisms;
- `revise_mechanism_text_from_evidence` for groups with the right scope but
  wrong or overly broad source/sink/guard wording;
- `collect_source_sink_guard_evidence` for groups whose evidence is too thin to
  support a stable guideline;
- `inspect_embedding_candidate_or_query_mismatch` for clean groups that still
  miss under the recall budget.
- `inspect_same_identity_recall_regression` for clean groups where the current
  recall run regresses against a same-identity baseline;
- `fix_recall_identity_join_or_run_coverage` for groups whose assigned cases do
  not appear in the recall table;
- `review_guideline_group_evidence` and `manual_review` for lower-confidence
  rows that need human source inspection before becoming release changes.

Judge-suggested guideline text is marked
`review_candidate_not_release`. It should be reread against source evidence
before entering `guideline_overrides.jsonl`; do not copy it directly into a
release and do not turn suggested phrases or example misses into runtime
matching rules.

Turn that backlog into a concrete evidence-collection worklist before changing
the generator or lexicon:

```bash
python new-impl/guideline-agent-pipeline/scripts/build_guideline_evidence_worklist.py \
  --revision-backlog new-impl/guideline-agent-pipeline/results/guideline-v2-r8-release-ready-group-eval-20260823/llm_judge_pack/revision_backlog_judge_only/revision_backlog.jsonl \
  --group-report new-impl/guideline-agent-pipeline/results/guideline-v2-r8-release-ready-group-eval-20260823/group_report.jsonl \
  --output-dir /path/to/guideline-evidence-worklist \
  --max-cases-per-item 6
```

Read `evidence_worklist.jsonl` as the next reviewer queue. Each row lists the
problematic guideline, action, mechanism, concrete evidence gaps, compact case
examples, and the next reviewer action. This step exists to prevent hardcoded
evaluation from shaping the generator: TraeX judge notes, labels, known
anchors, and bad cases are review hints only. They are not hidden routing
features and they are not release gates.

Extract the split/revise subset into a boundary repair pack:

```bash
python new-impl/guideline-agent-pipeline/scripts/build_guideline_boundary_repair_pack.py \
  --evidence-worklist new-impl/guideline-agent-pipeline/results/guideline-v2-r8-evidence-worklist-20260823/evidence_worklist.jsonl \
  --output-dir /path/to/guideline-boundary-repair-pack \
  --max-examples-per-state 3
```

Use `boundary_repair_pack.jsonl` before editing the mechanism lexicon or
guideline sidecar. It lists candidate split/revision boundaries and separates
source-backed examples from review-entry-only or missing-trace examples. The
boundaries are hypotheses until a reviewer assigns cases to them with checked
source/sink/guard/fix evidence.

Render per-guideline source-evidence review packets:

```bash
python new-impl/guideline-agent-pipeline/scripts/build_guideline_case_review_packets.py \
  --boundary-repair-pack new-impl/guideline-agent-pipeline/results/guideline-v2-r8-boundary-repair-pack-20260823/boundary_repair_pack.jsonl \
  --output-dir /path/to/guideline-case-review-packets
```

Use these packets for the next evidence-collection round. They are useful when
handing a specific mechanism group to a reviewer or source-inspection agent:
the reviewer fills the evidence fields, then the team decides whether to
promote a boundary into the lexicon or leave it out of the released sidecar.

Validate a filled reviewer ledger before promotion:

```bash
python new-impl/guideline-agent-pipeline/scripts/verify_guideline_review_ledger.py \
  --ledger /path/to/filled_guideline_review_ledger.jsonl \
  --output-dir /path/to/review-ledger-validation \
  --fail-on-invalid
```

Allowed `boundary_decision` values are `promote_boundary`, `revise_boundary`,
`split_further`, `mark_out_of_scope`, `needs_more_evidence`, and
`recall_side_debug`. Only `promote_boundary` rows with representative cases and
filled source/sink/missing-guard/exploit-precondition/fix fields are counted as
promotable; that still means semantically ready, not recall-proven.

Run a completion audit for the two-axis guideline objective:

```bash
python new-impl/guideline-agent-pipeline/scripts/audit_guideline_dual_axis_objective.py \
  --scorecard new-impl/guideline-agent-pipeline/results/guideline-v2-r8-release-ready-scorecard-20260823/scorecard.json \
  --evidence-worklist-summary new-impl/guideline-agent-pipeline/results/guideline-v2-r8-evidence-worklist-20260823/summary.json \
  --output-dir /path/to/guideline-dual-axis-objective-audit \
  --desired-delta-rate 0.10
```

Use this audit before declaring a guideline iteration complete. Passing
structural checks, TraeX judge parsing, sidecar equivalence, or a recall table
is not enough by itself. The completion gate requires semantic evidence for
the guideline taxonomy and same-identity recall evidence for the exact
sidecar/query configuration being claimed.

Convert the backlog into review-only mechanism lexicon proposals:

```bash
python new-impl/guideline-agent-pipeline/scripts/propose_mechanism_lexicon_updates.py \
  --revision-backlog new-impl/guideline-agent-pipeline/results/guideline-v2-r5-revision-backlog-20260823/revision_backlog.jsonl \
  --lexicon new-impl/guideline-agent-pipeline/guidelines/mechanism_lexicon.seed.json \
  --output-dir /path/to/lexicon-proposals
```

This proposal file is the handoff to the next guideline-design round. It can
name candidate mechanisms suggested by TraeX judge feedback, but those entries
are `release_ready=false` until a reviewer confirms they generalize beyond the
motivating cases and a fresh same-identity recall run confirms the effect.

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
