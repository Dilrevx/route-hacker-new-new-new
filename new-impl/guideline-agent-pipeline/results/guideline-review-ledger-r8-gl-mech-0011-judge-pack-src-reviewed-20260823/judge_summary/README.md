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
- Average scores: {'coherence_score': 0.665, 'coverage_score': 0.41, 'actionability_score': 0.51, 'retrieval_query_quality': 0.515}

## Highest Priority Rows

- `gl_mech_0011` `mech_archive_extraction_cycle_or_null_dos`: decision=needs_evidence, min_score=0.0, issue=Zero representative cases and zero evidence refs. The mechanism description (cyclic links, null entries, unbounded extraction loops causing DoS) is conceptually coherent, but without a single source-to-sink trace showing a concrete vulnerable extraction loop, null-sensitive parser, or unbounded recursion, the boundary is purely theoretical. The ledger row itself confirms this in all four guard fields — source_shape, sink_or_sensitive_effect, exploit_precondition, and safe_fix_semantics all explicitly state evidence is absent.
