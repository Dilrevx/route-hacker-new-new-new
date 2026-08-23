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
- Low-score groups: 2 at threshold 0.6
- Decision counts: {'accept': 4}
- Average scores: {'coherence_score': 0.8675, 'coverage_score': 0.5874999999999999, 'actionability_score': 0.8500000000000001, 'retrieval_query_quality': 0.8200000000000001}

## Highest Priority Rows

- `review_mech_0509` `mech_empty_token_reaches_auth_callback`: decision=accept, min_score=0.55, issue=The boundary is narrow (single representative case) but internally consistent: source shape (getattr producing empty string for missing token), sink (verify_token_callback invoked with empty string), missing guard (no non-empty check before callback dispatch), exploit precondition (attacker sends empty bearer/custom-header token), and safe fix (None sentinel + if token guard) all align tightly. The boundary text generalizes beyond Flask-HTTPAuth to any HTTP token-auth implementation that converts missing credentials to empty strings before callback invocation, which is a real and reusable pattern.
- `review_mech_0509` `mech_oidc_server_session_not_bound_to_token_expiry`: decision=accept, min_score=0.55, issue=Mechanism is coherent and well-sourced from a single CVE. Source shape, sink, missing guard, exploit precondition, and safe fix all align around the same OIDC session-timeout binding pattern. The reviewer notes correctly distinguish this from generic missing-auth-endpoint or JWT-claim-validation boundaries. Coverage is limited to one representative case, which is acceptable for a candidate boundary but may benefit from additional cases before promotion.
