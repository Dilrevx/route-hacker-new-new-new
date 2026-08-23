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
    "boundary_label": "candidate_boundary_03_nonempty_token_without_validation",
    "boundary_text": "Token-presence-only authentication: request interceptors or middleware read a session, JWT, API, or gateway token and allow protected handler execution when the token string is merely present or non-empty, without decrypting, verifying, decoding, or looking up the token before returning success. Report code paths where token validity is checked only for blankness before a protected endpoint or sensitive downstream operation proceeds.",
    "evidence_refs": [
      {
        "identity_key": "dtstack__taier::CVE-2026-11618",
        "source_evidence": "Patch commit f95389e7f74acec42bcee079a616aaa06f9551d2 adds TokenService to taier-data-develop/src/main/java/com/dtstack/taier/develop/interceptor/LoginInterceptor.java and calls tokenService.decryption(token) after the blank-token check and before returning true."
      },
      {
        "identity_key": "dtstack__taier::CVE-2026-11618",
        "source_evidence": "The same patch and issue context describe pre-auth remote code execution via authentication bypass plus JDBC URL injection. The auth bypass part is that LoginInterceptor previously checked only token presence before allowing source connection test endpoints."
      }
    ],
    "exploit_precondition": "An unauthenticated remote attacker can supply any non-empty token value to the intercepted endpoint and reach the protected datasource test flow.",
    "guideline_id": "review_mech_0514",
    "mechanism_id": "mech_token_presence_check_without_validation",
    "mechanism_name": "authentication interceptor accepts any non-empty token without validation",
    "missing_guard": "The vulnerable code throws NOT_LOGIN only when StringUtils.isBlank(token) and does not call TokenService.decryption(token), signature verification, session lookup, or equivalent validation before returning true.",
    "rationale": "The patch directly inserts token decryption/validation into the interceptor after a prior blankness-only guard. This supports a narrow reusable auth middleware mechanism.",
    "recall_follow_up": "After promoting this boundary into recall-consumed text, rerun same-identity recall for dtstack__taier::CVE-2026-11618. If recall misses, inspect whether candidate windows include LoginInterceptor.preHandle, CookieUtil.getCookieValue, StringUtils.isBlank(token), TokenService.decryption, and return true.",
    "representative_cases": [
      "dtstack__taier::CVE-2026-11618"
    ],
    "reviewer_notes": "This promoted boundary covers presence-only token acceptance. The same Taier patch also hardens JDBC URL parameters, but that is a separate injection/RCE sink and should not be merged into the authentication-interceptor guideline.",
    "safe_fix_semantics": "Inject the token validation service and validate/decrypt the token on the same interceptor path before returning true. Reject invalid tokens before entering protected handler logic, and separately block dangerous JDBC URL parameters at the datasource sink where applicable.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The interceptor returns true after only checking that the token is nonblank, allowing protected handlers such as source connection testing and the associated datasource/JDBC path to execute under an unauthenticated or forged token value.",
    "source_shape": "A Java Spring HandlerInterceptor reads an HTTP request token from cookies or headers and guards source-connection-test endpoints before the handler runs."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.