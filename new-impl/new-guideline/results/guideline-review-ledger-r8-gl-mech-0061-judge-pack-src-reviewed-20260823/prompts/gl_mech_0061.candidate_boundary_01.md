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
    "boundary_label": "candidate_boundary_01",
    "boundary_text": "Open redirect through missing final destination policy: an attacker-controlled redirect target, return URL, callback URL, Referer-derived destination, OAuth/OIDC redirect_uri, or client-side navigation target reaches a browser redirect, Location header, response.sendRedirect, window.location assignment, or protocol authorization redirect before the same source-to-sink path validates the final decoded and normalized destination against an exact policy. The relevant guard checks the destination that is actually emitted or assigned, not an earlier string form that can be bypassed by relative resolution, prefix matching, protocol-relative syntax, origin confusion, or unsafe URI schemes.",
    "evidence_refs": [
      {
        "identity_key": "aces__loris::CVE-2026-39985",
        "source_evidence": "The r8 case packet records modules/login/jsx/loginIndex.js Login.handleSubmit as the source-to-sink flow: after successful login, old client code assigns this.props.redirect directly to window.location.href when present. The patch parses the URL relative to window.location.origin and only navigates when the parsed origin matches."
      },
      {
        "identity_key": "dspace__dspace::CVE-2022-31193",
        "source_evidence": "The r8 case packet records dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java doDSGet: it reads callerUrl directly from the HTTP request and passes it to response.sendRedirect after only storing ID/filter session state. The patch adds a request context-path check before redirecting, confirming callerUrl to response.sendRedirect as the open-redirect path."
      },
      {
        "identity_key": "chamilo__chamilo-lms::CVE-2025-66447",
        "source_evidence": "The r8 case packet records assets/vue/composables/auth/login.js normalizeRedirectUrl as the fixed-side policy window for redirect query parameters, including relative path normalization, protocol validation, and same-origin checks. This supports the safe-fix semantics but is not used as the sole promotion evidence because the packet excerpt emphasizes the fixed guard rather than a complete old-side source-to-sink trace."
      }
    ],
    "exploit_precondition": "An attacker can supply or influence the redirect target through a request parameter, stored login redirect state, callback parameter, Referer-derived value, or similar web entry point, and can cause a victim or authenticated user to follow the vulnerable redirect flow.",
    "guideline_id": "gl_mech_0061",
    "mechanism_id": "mech_open_redirect_final_destination_policy_missing",
    "mechanism_name": "open redirect from attacker-controlled destination without final normalized policy check",
    "missing_guard": "The old-side paths do not validate the final parsed destination on the same path immediately before the redirect/navigation sink. The missing guard is not just scheme filtering: it must bind the actual emitted destination to a policy such as relative-only paths under the expected origin, exact registered callback URIs, or an allowlisted scheme/origin/path tuple. Prefix-only checks, unchecked request context, protocol-relative targets, ambiguous normalization, and direct assignment to window.location are insufficient.",
    "rationale": "The source-reviewed evidence supports a reusable redirect-destination policy mechanism broader than unsafe URI scheme bypass. It covers server-side and client-side browser navigation sinks where the exact final destination is not constrained before the sink.",
    "recall_follow_up": "If this boundary changes recall-consumed guideline text, rerun same-identity P3C64 recall first for aces__loris::CVE-2026-39985 and dspace__dspace::CVE-2022-31193, then rerun the frozen 143 identity set at Top-100, Top-150, and Top-200. Inspect whether the query retrieves redirect sink paths without using known anchors, CVE labels, or regex fallback in retrieval.",
    "representative_cases": [
      "aces__loris::CVE-2026-39985",
      "dspace__dspace::CVE-2022-31193"
    ],
    "safe_fix_semantics": "A safe fix parses and normalizes the destination using URL semantics before the sink, resolves relative paths against the expected application origin, rejects protocol-relative and malformed values, and allows only same-origin relative paths or exact registered/allowlisted destinations. The policy must be applied to the same normalized destination later used by sendRedirect, Location, window.location, or equivalent browser navigation effect.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The destination reaches a browser-visible navigation sink: LORIS assigns this.props.redirect directly to window.location.href after successful login, and DSpace passes request parameter callerUrl to response.sendRedirect in ControlledVocabularyServlet.doDSGet. The effect is that the application causes the user's browser to leave the trusted origin or navigate to an attacker-chosen location.",
    "source_shape": "The reviewed source-trace examples take a caller-influenced destination from login redirect state or HTTP request parameters and preserve it until the redirect/navigation operation. The destination may be a raw URL, path-like value, or request parameter that the application treats as a post-authentication or workflow continuation target."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.