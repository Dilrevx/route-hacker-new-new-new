# Guideline V2 Objective Audit

This note audits the current guideline-v2 state against the active research
objective:

```text
Design guideline generation that produces reusable, semantically accurate CVE
mechanism guidelines, while keeping those guidelines compatible with the tuned
embedding recall path. Bad recall cases can motivate revisions, but they must
not become answer keys or hardcoded routing. Engineering combinations need
cautious evidence because the work is paper-facing.
```

## Deliverables And Evidence

| Requirement | Current Evidence | Status |
| --- | --- | --- |
| Reusable guideline classification method | `scripts/generate_mechanism_guidelines.py` performs offline cluster-assisted mechanism attribution using a versioned mechanism lexicon, member-level evidence support, release-ready gating, and `pending_review` quarantine. | Partially satisfied |
| Generalizable but accurate CVE mechanism descriptions | r8 release has 177 released guidelines and 386 review-queue rows. Group eval reports weighted HCVR purity 0.8659 and weighted CWE purity 0.9245. TraeX judge over 20 sampled groups reports `accept=2`, `revise=5`, `split=3`, `needs_evidence=10`. | Not fully satisfied |
| Guideline works with tuned embedding recall | r7 full143 P3C64 recall is same-identity and complete: Top-100 76/143, Top-200 87/143. r8 sidecar is recall-consumed-text equivalent to r7: 189 shared keys and 0 changed consumed texts. | Satisfied for inherited r7/r8 sidecar behavior |
| Bad cases guide improvement without becoming answer keys | README records bad cases as motivation/regression data, while scripts keep known anchors out of query construction and only use them after ranking for Hit@K. | Satisfied by current code path |
| Avoid hardcoded online fallback | Online recall consumes explicit sidecars or dataset/template guidelines. Mechanism terms come from offline release artifacts; there is no online source-code regex scanner or per-case hidden routing. | Satisfied for online recall |
| Keep semantic quality and recall quality separate | Scorecard separates structural diagnostics, TraeX judge evidence, recall A/B evidence, and sidecar equivalence evidence. | Satisfied |
| Use TraeX LLM-as-judge appropriately | Judge rubric explicitly excludes embedding rank and known-anchor hit; judge output feeds a review backlog, not released guidelines or recall scoring. | Satisfied |
| Paper-facing claims are cautious | r8 scorecard marks recall as `inherited_same_identity_by_sidecar_equivalence`, not a fresh recall run, and marks improvement as `not_supported_at_desired_delta` at the default 10pp threshold. | Satisfied |

## Artifact Checklist

| Artifact | What It Covers |
| --- | --- |
| `results/mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/summary.json` | r8 release size, release-ready count, review queue count, sidecar row count |
| `results/guideline-v2-r8-release-ready-group-eval-20260823/summary.json` | structural grouping diagnostics over review-inclusive r8 rows |
| `results/guideline-v2-r8-release-ready-group-eval-20260823/llm_judge_pack/judge_summary/summary.json` | TraeX semantic review over 20 sampled guideline groups |
| `results/guideline-v2-r8-release-ready-group-eval-20260823/llm_judge_pack/revision_backlog_judge_only/` | judge-only next-step backlog |
| `results/guideline-v2-r7-full143-p3c64-20260823/old_p3c64_comparison.json` | same-identity r7 P3C64 recall comparison against old P3C64 |
| `results/guideline-v2-r8-vs-r7-sidecar-equivalence-20260823/summary.json` | proof that r8 and r7 sidecars are equivalent for recall-consumed text |
| `results/guideline-v2-r8-release-ready-scorecard-20260823/scorecard.json` | combined evidence boundary for release, judge, recall, and equivalence |

## Current Interpretation

r8 is cleaner as a release artifact than earlier iterations because unresolved
mechanisms remain in `review_queue.jsonl` and do not enter the default recall
sidecar. It is also recall-compatible with the measured r7 run because the
actual sidecar text consumed by recall is unchanged.

This does not prove that guideline generation is finished. The TraeX judge
sample still shows a semantic evidence bottleneck: only 2 of 20 reviewed groups
were accepted, while 10 need more source/sink/guard evidence, 5 need revised
wording, and 3 need split boundaries. The current paper-safe claim is therefore:

```text
r8 improves release hygiene and preserves the measured r7 recall behavior by
sidecar equivalence, but it does not yet establish a fresh >10pp recall
improvement or complete semantic guideline quality.
```

## Remaining Work

1. Improve source/sink/guard evidence extraction for `needs_evidence` groups
   before expanding the released sidecar.
2. Split or rewrite the concrete judge-flagged mechanisms instead of optimizing
   against structural purity flags or judge keywords.
3. Rerun same-identity P3C64 recall only after recall-consumed guideline text
   changes.
4. If semantically strong guidelines still miss recall, inspect query wording,
   candidate slicing, embedding backend, adapter weights, and ranking strategy
   before weakening the guideline taxonomy.
5. Keep TraeX LLM-as-judge as advisory semantic review. It may prioritize
   reviewer work, but it must not become a hidden label router or recall gate.

