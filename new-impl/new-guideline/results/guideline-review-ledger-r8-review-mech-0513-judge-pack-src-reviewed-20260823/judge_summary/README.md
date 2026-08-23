# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration, not as a hard scoring target.
Low scores and non-accept decisions identify groups worth reading; they should not be converted into keyword rules or hidden routing logic.

## Summary

- Judge inputs: 4
- Parsed outputs: 4
- Missing outputs: 0
- Invalid outputs: 0
- Accepted groups: 4
- Needs revision/split/merge/evidence: 0
- Low-score groups: 1 at threshold 0.6
- Decision counts: {'accept': 4}
- Average scores: {'coherence_score': 0.875, 'coverage_score': 0.5874999999999999, 'actionability_score': 0.7125, 'retrieval_query_quality': 0.6250000000000001}

## Highest Priority Rows

- `review_mech_0513` `pending_mech_jwt_signature_verification_unreviewed_members`: decision=accept, min_score=0.1, issue=The boundary is internally coherent and correctly self-limits: it explicitly states that the three remaining cases lack source-reviewed evidence and should not be used as positives for recall or guideline routing. The boundary text is a well-formed placeholder that prevents label-pressure from contaminating the three promoted submechanisms. The decision of needs_more_evidence is appropriate for the actual cases, and the boundary itself is accept-quality as a negative/holding boundary.
