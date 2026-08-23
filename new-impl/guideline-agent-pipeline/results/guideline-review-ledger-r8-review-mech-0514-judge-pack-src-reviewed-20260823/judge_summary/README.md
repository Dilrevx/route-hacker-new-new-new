# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration, not as a hard scoring target.
Low scores and non-accept decisions identify groups worth reading; they should not be converted into keyword rules or hidden routing logic.

## Summary

- Judge inputs: 5
- Parsed outputs: 5
- Missing outputs: 0
- Invalid outputs: 0
- Accepted groups: 4
- Needs revision/split/merge/evidence: 1
- Low-score groups: 4 at threshold 0.6
- Decision counts: {'accept': 4, 'needs_evidence': 1}
- Average scores: {'coherence_score': 0.73, 'coverage_score': 0.45000000000000007, 'actionability_score': 0.71, 'retrieval_query_quality': 0.6700000000000002}

## Highest Priority Rows

- `review_mech_0514` `pending_mech_authentication_authorization_flow_unreviewed_members`: decision=needs_evidence, min_score=0.1, issue=This boundary is explicitly a quarantine holding row, not a coherent mechanism. The two representative cases belong to different mechanism families: CVE-2021-29455 involves JWT refresh-token signature verification failure, while CVE-2025-62604 involves an unauthenticated login flow bypass. The source shape, missing guard, sink, exploit precondition, and safe fix are all marked as 'needs per-case review' with no shared mechanism to judge.
- `review_mech_0514` `mech_inactive_identifier_authentication_acceptance`: decision=accept, min_score=0.5, issue=Single-case boundary with intentionally narrow scope. The mechanism is internally coherent — source shape (getByUsernameUnsafe lookup), sink (getAccountById returning authenticated account), missing guard (no active-identifier check between credential resolution and account return), exploit precondition (attacker controls credentials for an inactive but resolvable identifier), and safe fix (insert checkIdentifier before password/no-password return paths) all align tightly. The patch evidence from commit 9783b1143da6576028de23e15a1f198b1f937b82 is direct and unambiguous. The reviewer notes preemptively justify the narrow scope and explicitly warn against merging with JWT validation, missing-token-rejection, or resource-scope authorization boundaries. Generalizability to other codebases with similar inactive-identifier patterns is plausible but unproven with only one case.
- `review_mech_0514` `mech_token_presence_check_without_validation`: decision=accept, min_score=0.5, issue=Only one representative case (dtstack__taier::CVE-2026-11618). The mechanism is well-defined and the patch evidence directly supports the pattern, but broader coverage across more projects would raise confidence in generalizability.
- `review_mech_0514` `mech_empty_token_scope_satisfies_required_scope`: decision=accept, min_score=0.55, issue=Only one representative case (CVE-2025-53003). The mechanism is internally coherent with strong patch-level evidence, but generalizability beyond the Janssen project is unproven.
