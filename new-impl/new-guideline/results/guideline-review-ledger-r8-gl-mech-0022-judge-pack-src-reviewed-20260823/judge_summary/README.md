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
- Average scores: {'coherence_score': 0.925, 'coverage_score': 0.675, 'actionability_score': 0.875, 'retrieval_query_quality': 0.8400000000000001}

## Highest Priority Rows

- `gl_mech_0022` `mech_xml_namespace_location_loading`: decision=accept, min_score=0.5, issue=Single representative case limits coverage, but the mechanism is coherently defined and well-evidenced. The boundary correctly distinguishes namespace/package URI location loading from classic XXE (parser features already disabled). The recall_follow_up field appropriately acknowledges the need for future same-identity recall expansion.
