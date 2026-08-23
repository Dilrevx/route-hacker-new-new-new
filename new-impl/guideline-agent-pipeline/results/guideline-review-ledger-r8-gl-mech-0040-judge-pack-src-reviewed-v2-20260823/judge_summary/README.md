# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration, not as a hard scoring target.
Low scores and non-accept decisions identify groups worth reading; they should not be converted into keyword rules or hidden routing logic.

## Summary

- Judge inputs: 6
- Parsed outputs: 6
- Missing outputs: 0
- Invalid outputs: 0
- Accepted groups: 4
- Needs revision/split/merge/evidence: 2
- Low-score groups: 3 at threshold 0.6
- Decision counts: {'accept': 4, 'needs_evidence': 2}
- Average scores: {'coherence_score': 0.7333333333333334, 'coverage_score': 0.5416666666666666, 'actionability_score': 0.67, 'retrieval_query_quality': 0.6883333333333334}

## Highest Priority Rows

- `gl_mech_0040` `mech_template_expression_untrusted_eval`: decision=needs_evidence, min_score=0.1, issue=The row correctly identifies that the 7 historical members of gl_mech_0040 span multiple evaluator technologies (FreeMarker, AviatorScript, Bean Validation EL, general EL) and lack per-case source review for source shape, sink, missing guard, exploit precondition, and fix semantics. The boundary decision to withhold promotion until source evidence is collected is prudent and well-founded.
- `gl_mech_0040` `mech_parser_error_message_downstream_el_risk`: decision=needs_evidence, min_score=0.2, issue=The mechanism is conceptually coherent but the sink half is entirely hypothetical. The patch only proves that raw attacker input was removed from an error message; there is no source-reviewed evidence that the resulting exception message reaches an EL-capable interpolation sink (e.g., buildConstraintViolationWithTemplate, JEXL, or a UI template engine). Without confirming the downstream sink, the boundary cannot be promoted or used for reliable recall.
- `gl_mech_0040` `mech_spel_unrestricted_evaluation_context`: decision=accept, min_score=0.3, issue=Single-case coverage is inherently limited, but the mechanism is narrow, specific, and internally coherent. The evidence is solid: a concrete fix commit replacing StandardEvaluationContext with SimpleEvaluationContext across multiple notifier paths. The boundary text names specific classes, APIs, and guard conditions, making it highly retrievable and actionable.
