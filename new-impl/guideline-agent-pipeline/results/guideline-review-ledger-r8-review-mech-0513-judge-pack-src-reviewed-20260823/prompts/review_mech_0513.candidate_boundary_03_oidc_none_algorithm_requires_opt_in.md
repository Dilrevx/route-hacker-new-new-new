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
    "boundary_label": "candidate_boundary_03_oidc_none_algorithm_requires_opt_in",
    "boundary_text": "OIDC unsigned ID token acceptance: OpenID Connect client configuration builds an ID token validator for provider-advertised `none` JWS algorithm values without an explicit application opt-in. Report code paths where unsigned ID tokens can be accepted by default, or where `none` algorithm support is enabled implicitly, before user identity/profile claims are trusted.",
    "evidence_refs": [
      {
        "identity_key": "pac4j__pac4j::CVE-2021-44878",
        "source_evidence": "Patch commit 22b82ffd702a132d9f09da60362fc6264fc281ae adds OidcConfiguration.allowUnsignedIdTokens with documentation that the `none` algorithm for ID tokens means no signature validation and must be explicitly accepted."
      },
      {
        "identity_key": "pac4j__pac4j::CVE-2021-44878",
        "source_evidence": "The same patch changes TokenValidator.java:51-64 so `none` now throws `Unsigned ID tokens are not allowed` unless configuration.isAllowUnsignedIdTokens() is true; previously `none` was converted to null and an unsigned IDTokenValidator was built."
      },
      {
        "identity_key": "pac4j__pac4j::CVE-2021-44878",
        "source_evidence": "The added TokenValidatorTests include testNoneAlgoNotAllowed and testNoneAlgoAllowed, confirming both the missing guard and the intended explicit opt-in fix semantics."
      }
    ],
    "exploit_precondition": "An attacker can influence or abuse an OIDC flow where provider metadata or token handling permits `none` as the ID token algorithm and the client accepts the unsigned token for identity claims.",
    "guideline_id": "review_mech_0513",
    "mechanism_id": "mech_oidc_unsigned_id_token_default_allowed",
    "mechanism_name": "OIDC unsigned ID token accepted without explicit opt-in",
    "missing_guard": "The vulnerable code treats `none` as a null algorithm and creates an unsigned IDTokenValidator without requiring an explicit allowUnsignedIdTokens configuration decision.",
    "rationale": "The patch directly changes OIDC validator construction so unsigned ID tokens are rejected unless explicitly enabled. This supports a narrow source-reviewed mechanism boundary.",
    "recall_follow_up": "After a sidecar change, rerun same-identity recall for pac4j__pac4j::CVE-2021-44878 and inspect whether candidate windows include OidcConfiguration, TokenValidator, provider JWS algorithms, IDTokenValidator, and allowUnsignedIdTokens.",
    "representative_cases": [
      "pac4j__pac4j::CVE-2021-44878"
    ],
    "reviewer_notes": "This is an OIDC protocol-configuration mechanism, not a generic JWT parser bug. It shares the authentication-token validation domain with the JJWT and Authlib rows, but the useful audit query should name OIDC ID token `none` algorithm handling and explicit unsigned-token opt-in.",
    "safe_fix_semantics": "Introduce an explicit allowUnsignedIdTokens configuration flag defaulting to false, reject `none` unless that flag is enabled, and surface the configuration in documentation/tests. The guard must occur before constructing the unsigned IDTokenValidator.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "When the provider metadata includes `none`, the vulnerable code constructs an IDTokenValidator that accepts unsigned ID tokens. Accepted ID token claims are then used for OIDC user profile creation and authentication decisions.",
    "source_shape": "An OIDC client reads provider metadata containing ID token JWS algorithms and constructs per-algorithm IDTokenValidator instances during configuration initialization."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.