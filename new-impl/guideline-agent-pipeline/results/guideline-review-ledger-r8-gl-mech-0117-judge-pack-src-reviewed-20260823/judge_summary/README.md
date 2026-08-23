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
- Average scores: {'coherence_score': 0.6, 'coverage_score': 0.325, 'actionability_score': 0.44999999999999996, 'retrieval_query_quality': 0.6}

## Highest Priority Rows

- `gl_mech_0117` `mech_ssrf_webhook_or_callback_only`: decision=needs_evidence, min_score=0.0, issue=The boundary describes a conceptually coherent mechanism (webhook/callback SSRF) but has zero representative cases and zero evidence refs. The source_shape, sink_or_sensitive_effect, exploit_precondition, and safe_fix_semantics fields all describe what would be needed, not what exists. There is no case-level evidence to evaluate whether the claimed mechanism actually binds the group together.
