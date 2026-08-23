# Guideline Semantic Judge Rubric

You are judging a reusable security-audit guideline group.

Evaluate whether the guideline accurately describes a coherent vulnerability
mechanism shared by the listed cases.

Do not evaluate embedding recall, rank, or whether known anchors were hit.
Do not require all cases to share the same CWE or dataset label; those labels
are only weak context.

Prefer mechanism-level judgments:

- source shape
- sink shape
- missing guard
- exploit precondition
- safe fix

Return JSON only with this schema:

```json
{
  "decision": "accept|revise|split|merge|needs_evidence",
  "coherence_score": 0.0,
  "coverage_score": 0.0,
  "actionability_score": 0.0,
  "retrieval_query_quality": 0.0,
  "main_issue": "short explanation",
  "suggested_guideline": "rewrite if decision is revise or split",
  "split_suggestions": ["submechanism A", "submechanism B"],
  "evidence_notes": ["case-level evidence or missing evidence"]
}
```

Ledger-specific instructions:
{
  "decision_values": [
    "accept",
    "revise",
    "split",
    "merge",
    "needs_evidence"
  ],
  "expected_json": {
    "actionability_score": 0.0,
    "coherence_score": 0.0,
    "coverage_score": 0.0,
    "decision": "accept|revise|split|merge|needs_evidence",
    "evidence_notes": [
      "case-level evidence or missing evidence"
    ],
    "main_issue": "short explanation",
    "retrieval_query_quality": 0.0,
    "split_suggestions": [
      "submechanism A",
      "submechanism B"
    ],
    "suggested_guideline": "rewrite if decision is revise or split"
  },
  "review_scope": [
    "Judge semantic boundary quality only.",
    "Check whether source shape, sink/effect, missing guard, exploit precondition, and safe fix are coherent.",
    "Check whether representative cases support the boundary decision.",
    "Do not judge embedding recall, known-anchor rank, Top-K metrics, or model performance.",
    "Do not invent new source evidence. If evidence is insufficient, return needs_evidence.",
    "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only."
  ],
  "task": "Review one source-reviewed guideline boundary ledger row."
}

Ledger boundary payload:
{
  "judge_mode": "source_reviewed_boundary_advisory",
  "ledger_row": {
    "boundary_decision": "promote_boundary",
    "boundary_label": "candidate_boundary_04_empty_token_scope_authorization_bypass",
    "boundary_text": "Empty-token-scope authorization bypass: authorization helpers compare resource-required scopes against scopes carried by an access token, but treat an empty or missing token-scope list as if no required scopes are missing. Report code paths where a token without the required scope can access protected API resources because the missing-scope calculation returns an empty difference for both empty required-scope and empty token-scope inputs.",
    "evidence_refs": [
      {
        "identity_key": "janssenproject__jans::CVE-2025-53003",
        "source_evidence": "Patch commit 92eea4d4637f1cae16ad2f07b2c16378ff3fc5f1 changes AuthUtil.findMissingElements so it returns Collections.emptyList() only when the required-scope list is empty; when token scopes are null or empty, it now returns list1 as missing."
      },
      {
        "identity_key": "janssenproject__jans::CVE-2025-53003",
        "source_evidence": "The same patch updates OpenIdAuthorizationService.validateScope to explicitly return success only for resources with no required scopes, and adds ClientResourceTest.getClientsWithInvalidToken expecting HTTP 401 for a token with an unrelated scope."
      },
      {
        "identity_key": "janssenproject__jans::CVE-2025-53003",
        "source_evidence": "The public advisory states Janssen Config API returned results without scope verification and that the flaw exposed IDP information from clients, users, scripts, and related internal API surfaces."
      }
    ],
    "exploit_precondition": "An attacker obtains or supplies an access token that is accepted by the service but lacks the specific scope required by the target config API endpoint.",
    "guideline_id": "review_mech_0514",
    "mechanism_id": "mech_empty_token_scope_satisfies_required_scope",
    "mechanism_name": "empty token scope set treated as satisfying required resource scopes",
    "missing_guard": "The vulnerable AuthUtil.findMissingElements helper returns Collections.emptyList() when either the required-scope list or token-scope list is null/empty, so an empty token-scope list satisfies any nonempty resource requirement.",
    "rationale": "The patch directly corrects the empty token-scope branch and adds a negative authorization test. This supports a reusable resource-scope authorization boundary.",
    "recall_follow_up": "After a sidecar change, rerun same-identity recall for janssenproject__jans::CVE-2025-53003. Inspect whether candidate windows include OpenIdAuthorizationService.validateScope, AuthUtil.findMissingElements, tokenScopes, resourceScopes, missingScopes, and unauthorized test expectations.",
    "representative_cases": [
      "janssenproject__jans::CVE-2025-53003"
    ],
    "reviewer_notes": "This is an authorization-scope difference bug, not a generic authentication-token parser issue. It should be queried using required scopes, token scopes, missing scopes, and protected API resource access.",
    "safe_fix_semantics": "Return no missing scopes only when the resource-required scope list itself is empty. If token scopes are null or empty while resource scopes are required, return the full required scope list as missing and reject the request.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "Protected config API endpoints can return identity-provider data such as clients, users, scripts, or other administrative resources when the token lacks the required scope but the authorization helper concludes no scopes are missing.",
    "source_shape": "A Java configuration API validates an OAuth access token against resource-specific required scopes before forwarding the Authorization header to internal API handlers."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.