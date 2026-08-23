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
- Average scores: {'coherence_score': 0.425, 'coverage_score': 0.4, 'actionability_score': 0.425, 'retrieval_query_quality': 0.4}

## Highest Priority Rows

- `gl_mech_0061` `mech_open_redirect_unsafe_uri_scheme_only`: decision=needs_evidence, min_score=0.0, issue=No representative cases or evidence refs are attached to this boundary. The ledger row itself acknowledges that the old guideline over-focused on URI schemes while the evidence supports a broader final-destination policy boundary. Without at least one source-reviewed case showing unsafe scheme handling as the primary bypass mechanism (with a concrete source-to-sink trace, exploit precondition, and fix evidence), semantic coherence cannot be assessed.
