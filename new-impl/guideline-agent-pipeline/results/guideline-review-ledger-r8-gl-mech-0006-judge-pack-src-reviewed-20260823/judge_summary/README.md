# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration, not as a hard scoring target.
Low scores and non-accept decisions identify groups worth reading; they should not be converted into keyword rules or hidden routing logic.

## Summary

- Judge inputs: 2
- Parsed outputs: 2
- Missing outputs: 0
- Invalid outputs: 0
- Accepted groups: 2
- Needs revision/split/merge/evidence: 0
- Low-score groups: 1 at threshold 0.6
- Decision counts: {'accept': 2}
- Average scores: {'coherence_score': 0.875, 'coverage_score': 0.5249999999999999, 'actionability_score': 0.825, 'retrieval_query_quality': 0.7250000000000001}

## Highest Priority Rows

- `gl_mech_0006` `mech_absolute_resource_path_traversal_missing_component_validation`: decision=accept, min_score=0.35, issue=Mechanism is internally coherent and well-evidenced for the single representative case, but boundary generality across multiple cases is not demonstrated.
