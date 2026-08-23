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
    "boundary_label": "candidate_boundary_01_inactive_identifier_authentication_acceptance",
    "boundary_text": "Inactive identifier authentication acceptance: authentication code looks up credentials by an externally supplied username, email, phone number, or other login identifier and accepts the account after password or credential verification without confirming that the matched identifier is active and still allowed for login. Report code paths where inactive, disabled, unverified, or revoked identifiers can still bind to an account or principal before session creation or authentication success.",
    "evidence_refs": [
      {
        "identity_key": "authguard__authguard::CVE-2021-45890",
        "source_evidence": "Patch commit 9783b1143da6576028de23e15a1f198b1f937b82 has subject `Prevent authentication with inactive identifiers`. It adds checkIdentifier(credentials, username) before both password and no-password account return paths in basic-auth/src/main/java/com/nexblocks/authguard/basic/BasicAuthProvider.java."
      },
      {
        "identity_key": "authguard__authguard::CVE-2021-45890",
        "source_evidence": "The same patch adds checkIdentifier to find the submitted identifier in credentials.getIdentifiers(), reject missing matches, and return ServiceAuthorizationException(ErrorCode.INACTIVE_IDENTIFIER) when matchedIdentifier.isActive() is false. The added authenticateInactiveIdentifier test asserts inactive identifiers fail authentication."
      }
    ],
    "exploit_precondition": "An attacker knows or controls credentials for an identifier that remains resolvable by getByUsernameUnsafe but is marked inactive, disabled, or otherwise not valid for authentication.",
    "guideline_id": "review_mech_0514",
    "mechanism_id": "mech_inactive_identifier_authentication_acceptance",
    "mechanism_name": "inactive account identifier accepted during authentication",
    "missing_guard": "The vulnerable code does not check that the specific UserIdentifier matching the submitted username is active before accepting the credential and returning the account.",
    "rationale": "The patch directly inserts the missing active-identifier check on the authentication path and adds a regression test for inactive identifiers. This supports a narrow source-reviewed mechanism.",
    "recall_follow_up": "After promoting this boundary into recall-consumed text, rerun same-identity recall for authguard__authguard::CVE-2021-45890. If recall misses, inspect whether candidate windows include BasicAuthProvider.verifyCredentialsAndGetAccount, credentials.getIdentifiers, UserIdentifier.isActive, and getAccountById before changing the boundary.",
    "representative_cases": [
      "authguard__authguard::CVE-2021-45890"
    ],
    "reviewer_notes": "This is a specific authentication-state boundary. It should not be merged with JWT signature validation, missing token rejection, or resource-scope authorization because the source object is a credential identifier and the guard is active identifier state.",
    "safe_fix_semantics": "Before password acceptance or username-only account return, locate the matching identifier on the credential record and reject authentication when that identifier is missing or inactive. The fix must run on the same credential path that creates the authenticated account.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The provider verifies the supplied password or accepts the username-only path, then returns getAccountById(credentials.getAccountId()) as an authenticated account. If the matched identifier is inactive, authentication succeeds for a credential identity that should no longer be valid.",
    "source_shape": "A Java basic-auth provider receives an attacker-supplied username and password and uses credentialsService.getByUsernameUnsafe(username) to locate credentials and account identifiers."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.