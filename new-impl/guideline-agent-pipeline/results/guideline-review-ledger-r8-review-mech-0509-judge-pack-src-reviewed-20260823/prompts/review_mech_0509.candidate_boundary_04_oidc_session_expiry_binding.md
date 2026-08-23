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
    "boundary_label": "candidate_boundary_04_oidc_session_expiry_binding",
    "boundary_text": "OIDC session lifetime not bound to token expiry: a web application establishes a server-side session for OIDC login but leaves the servlet/session timeout or OpenID configuration independent of provider token expiration, allowing an authenticated server session to remain valid beyond the intended inactivity or ID-token lifetime. Report security-handler or OIDC configuration paths where session lifetime and logout-on-token-expiry controls are absent on the same authentication flow.",
    "evidence_refs": [
      {
        "identity_key": "datasharingframework__dsf::CVE-2026-40939",
        "source_evidence": "Patch f4ecb002f7d12642f92da6b79371ed367d0140e7 adds configuration property `dev.dsf.server.auth.oidc.session.timeout:PT30M` and helper `oidcSessionTimeout()`."
      },
      {
        "identity_key": "datasharingframework__dsf::CVE-2026-40939",
        "source_evidence": "In `AbstractJettyConfig.configureSecurityHandler`, the patch adds `sessionHandler.setMaxInactiveInterval(oidcSessionTimeout())` and changes `new OpenIdConfiguration.Builder(...).httpClient(...).build()` to `new OpenIdConfiguration.Builder(...).logoutWhenIdTokenIsExpired(true).httpClient(...).build()`."
      }
    ],
    "exploit_precondition": "OIDC authorization-code login or related OIDC auth modes are enabled, a user obtains a server-side session, and the deployment expects inactivity or ID-token expiry to terminate that session. Without the binding, stale sessions can remain usable past the intended authentication lifetime.",
    "guideline_id": "review_mech_0509",
    "mechanism_id": "mech_oidc_server_session_not_bound_to_token_expiry",
    "mechanism_name": "OIDC server session not bounded to token expiry",
    "missing_guard": "The vulnerable configuration does not call `sessionHandler.setMaxInactiveInterval(...)` with an OIDC session timeout and does not set `.logoutWhenIdTokenIsExpired(true)` on the OpenIdConfiguration used by the OIDC security handler.",
    "rationale": "The patch adds exactly the missing session timeout and OIDC token-expiry logout bindings on the security-handler construction path.",
    "recall_follow_up": "After sidecar update, rerun same-identity recall for datasharingframework__dsf::CVE-2026-40939. Candidate slices should include `AbstractJettyConfig.configureSecurityHandler`, `SessionHandler`, `OpenIdConfiguration.Builder`, `setMaxInactiveInterval`, and `logoutWhenIdTokenIsExpired`.",
    "representative_cases": [
      "datasharingframework__dsf::CVE-2026-40939"
    ],
    "reviewer_notes": "This is session-lifetime binding for OIDC, not a generic missing authentication endpoint and not JWT claim validation. Keep it separate so recall queries can include OIDC, Jetty SessionHandler, max inactive interval, ID token expiry, and logout semantics.",
    "safe_fix_semantics": "Add an explicit positive OIDC session timeout configuration, apply it to the Jetty `SessionHandler` with `setMaxInactiveInterval`, and build the OpenIdConfiguration with `logoutWhenIdTokenIsExpired(true)` so server session validity tracks OIDC token/session lifetime.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The server-side session created through OIDC-backed authentication can remain active according to generic container defaults rather than the configured OIDC inactivity and ID-token expiry policy. This affects authentication lifetime and continued access to protected server functions.",
    "source_shape": "DSF configures Jetty security and OIDC login in `AbstractJettyConfig.configureSecurityHandler`. The vulnerable flow obtains the web app session handler and creates an `OpenIdConfiguration` for the provider, client ID, and client secret without applying an OIDC-specific server-session inactivity timeout or token-expiry logout behavior."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.