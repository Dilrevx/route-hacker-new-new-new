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
    "boundary_label": "candidate_boundary_02_empty_token_callback",
    "boundary_text": "Empty token accepted by authentication callback: an HTTP token-authentication implementation extracts a bearer token, custom header token, API key, or similar credential into an empty string when the credential is missing or blank, and still invokes the configured verification callback. Report code paths where blank credentials can enter identity validation or produce an authenticated principal instead of being rejected before callback dispatch.",
    "evidence_refs": [
      {
        "identity_key": "miguelgrinberg__flask-httpauth::CVE-2026-34531",
        "source_evidence": "Patch b15ffe9e50e110d7174ccd944f642079e1dcf9ee is titled `Do not accept empty tokens`. In `src/flask_httpauth.py`, old code used `token = getattr(auth, 'token', '')` followed by `if self.verify_token_callback:`; the patch changes this to `token = getattr(auth, 'token', None)` and `if token and self.verify_token_callback:`."
      },
      {
        "identity_key": "miguelgrinberg__flask-httpauth::CVE-2026-34531",
        "source_evidence": "The patch adds tests `test_token_auth_login_empty_token` and `test_token_auth_custom_header_empty_token`, both expecting HTTP 401 for empty token inputs. The verifier test callbacks assert that token is non-empty."
      }
    ],
    "exploit_precondition": "An attacker can send a token-authenticated request with an empty bearer token or empty custom token header to an application using Flask-HTTPAuth token callbacks, and the application's callback or surrounding logic can treat that empty value as accepted or otherwise fail open.",
    "guideline_id": "review_mech_0509",
    "mechanism_id": "mech_empty_token_reaches_auth_callback",
    "mechanism_name": "empty bearer or custom token reaches authentication callback",
    "missing_guard": "The vulnerable path did not require the token value to be non-empty before invoking the verification callback. The missing guard is a local credential-presence check on the same `token` value that reaches callback-based identity establishment.",
    "rationale": "The source diff and tests show that the defect is specifically a blank-token credential-presence bug before callback authentication.",
    "recall_follow_up": "After sidecar update, rerun same-identity recall for miguelgrinberg__flask-httpauth::CVE-2026-34531. Candidate slices should include `HTTPTokenAuth.authenticate`, `getattr(auth, 'token', ...)`, `verify_token_callback`, and empty-token regression tests/fix context.",
    "representative_cases": [
      "miguelgrinberg__flask-httpauth::CVE-2026-34531"
    ],
    "reviewer_notes": "This boundary is narrower than missing authentication before privileged action. It should route auditors to token parsing, credential presence, and callback invocation semantics rather than endpoint permission annotations.",
    "safe_fix_semantics": "Represent missing tokens as `None` and require `if token and self.verify_token_callback` before calling the verifier. Add regression tests asserting that empty Authorization and custom-token headers return 401 and do not call verifier logic with an empty string.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The empty string was passed into `verify_token_callback` whenever the callback existed. Applications whose callback mishandled empty strings could authenticate a request that lacked a real token, allowing protected routes to be reached.",
    "source_shape": "Flask-HTTPAuth's token authentication path receives parsed HTTP authentication data and reads `auth.token`. The vulnerable code used `getattr(auth, 'token', '')`, so a missing token became an empty string."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.