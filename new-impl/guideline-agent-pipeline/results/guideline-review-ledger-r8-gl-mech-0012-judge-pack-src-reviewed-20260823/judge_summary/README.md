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
- Average scores: {'coherence_score': 0.675, 'coverage_score': 0.425, 'actionability_score': 0.5, 'retrieval_query_quality': 0.6}

## Highest Priority Rows

- `gl_mech_0012` `mech_message_from_dict_missing_html_sanitization`: decision=needs_evidence, min_score=0.15, issue=The advisory describes a coherent stored-XSS mechanism through AppLollmsMessage.from_dict deserialization without sanitization, but the referenced commit 9767b882 only touches social routes, direct-message routes, and a migration script — not backend/message.py. Raw file checks confirm the from_dict assignment content=data.get("content", "") is unchanged between parent and patch. The boundary cannot be accepted, revised, split, or merged until the actual source delta proving the described from_dict fix is located.
