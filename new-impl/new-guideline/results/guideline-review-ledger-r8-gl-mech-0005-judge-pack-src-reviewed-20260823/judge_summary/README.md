# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration, not as a hard scoring target.
Low scores and non-accept decisions identify groups worth reading; they should not be converted into keyword rules or hidden routing logic.

## Summary

- Judge inputs: 2
- Parsed outputs: 2
- Missing outputs: 0
- Invalid outputs: 0
- Accepted groups: 1
- Needs revision/split/merge/evidence: 1
- Low-score groups: 1 at threshold 0.6
- Decision counts: {'accept': 1, 'needs_evidence': 1}
- Average scores: {'coherence_score': 0.5, 'coverage_score': 0.4, 'actionability_score': 0.55, 'retrieval_query_quality': 0.575}

## Highest Priority Rows

- `gl_mech_0005` `mech_path_traversal_review_entry_or_partial_evidence`: decision=needs_evidence, min_score=0.0, issue=This boundary describes an evidentiary holding queue, not a coherent vulnerability mechanism. No representative cases are listed, and every mechanism dimension (source shape, sink, missing guard, exploit precondition, safe fix) is 'needs per-case evidence.' The cases share only that they lack sufficient source review — they may not share the same path-traversal submechanism at all. As a semantic guideline, it has no mechanism-level content to judge.
