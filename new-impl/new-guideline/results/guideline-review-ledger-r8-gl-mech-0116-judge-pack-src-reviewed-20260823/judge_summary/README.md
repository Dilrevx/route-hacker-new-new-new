# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration, not as a hard scoring target.
Low scores and non-accept decisions identify groups worth reading; they should not be converted into keyword rules or hidden routing logic.

## Summary

- Judge inputs: 3
- Parsed outputs: 3
- Missing outputs: 0
- Invalid outputs: 0
- Accepted groups: 2
- Needs revision/split/merge/evidence: 1
- Low-score groups: 1 at threshold 0.6
- Decision counts: {'accept': 2, 'needs_evidence': 1}
- Average scores: {'coherence_score': 0.8233333333333333, 'coverage_score': 0.5833333333333334, 'actionability_score': 0.7666666666666666, 'retrieval_query_quality': 0.75}

## Highest Priority Rows

- `gl_mech_0116` `mech_ssrf_redirect_following_client`: decision=needs_evidence, min_score=0.1, issue=The guideline text is internally coherent as a standalone vulnerability mechanism (source shape, sink, missing guard, exploit precondition, and safe fix all align around redirect-following SSRF), but the source-reviewed evidence does not establish redirect-following as the shared boundary for any of the cases in this group. The representative_cases list is empty, and the rationale explicitly states that gl_mech_0116 examples mostly establish direct URL/proxy SSRF, renderer external-resource SSRF, or credential/trust-boundary confusion—not redirect-following.
