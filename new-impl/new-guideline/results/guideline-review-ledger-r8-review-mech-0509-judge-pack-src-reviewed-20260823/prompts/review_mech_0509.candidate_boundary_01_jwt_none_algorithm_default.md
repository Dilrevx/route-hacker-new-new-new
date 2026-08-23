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
    "boundary_label": "candidate_boundary_01_jwt_none_algorithm_default",
    "boundary_text": "JWT none-algorithm default acceptance: a JWT helper, decoder, encoder, request-object parser, userinfo endpoint, or token utility constructs its default allowed-algorithm set from every registered JWS algorithm, including the unsecured `none` algorithm, and then uses that default for authentication or identity-bearing token operations. Report code paths where unsigned JWTs can be accepted or generated without an explicit per-call opt-in to `none`.",
    "evidence_refs": [
      {
        "identity_key": "authlib__authlib::CVE-2026-28802",
        "source_evidence": "Patch b87c32ed07b8ae7f805873e1c9cafd1016761df7 is titled `fix: remove \"none\" algorithm from default jwt instance`. The old code in `authlib/jose/__init__.py` set `jwt = JsonWebToken(list(JsonWebSignature.ALGORITHMS_REGISTRY.keys()))`; the patch replaces it with an explicit signed algorithm list and moves intentional none-algorithm behavior to local `JsonWebToken([\"none\"])` instances in tests."
      },
      {
        "identity_key": "authlib__authlib::CVE-2026-28802",
        "source_evidence": "The same patch changes OAuth2/OIDC helpers from importing the default `jwt` object to constructing `JsonWebToken(...)` with context-specific algorithms, including `_decode_request_object` and userinfo/id-token encoding paths."
      }
    ],
    "exploit_precondition": "A relying application uses Authlib's default `jwt` helper or an affected OAuth/OIDC helper path to process JWT artifacts and accepts attacker-supplied or protocol-supplied JWT content where unsigned `alg=none` tokens should not be trusted by default.",
    "guideline_id": "review_mech_0509",
    "mechanism_id": "mech_jwt_default_allows_none_algorithm",
    "mechanism_name": "JWT default verifier includes unsigned none algorithm",
    "missing_guard": "The vulnerable default does not exclude `none` from the general-purpose allowed algorithm list and does not require callers to instantiate an explicit `JsonWebToken([\"none\"])` object for unsecured JWT behavior. The guard must be bound to default construction of the token helper used by auth flows, not only to test code.",
    "rationale": "The patch directly removes `none` from the default JWT helper and forces explicit opt-in for unsecured JWT usage, establishing a precise auth-token mechanism.",
    "recall_follow_up": "After this boundary is promoted into recall-consumed sidecar text, rerun same-identity recall for authlib__authlib::CVE-2026-28802 at Top-100, Top-150, and Top-200. Inspect whether candidate slices include `authlib/jose/__init__.py`, `JsonWebToken`, `JsonWebSignature.ALGORITHMS_REGISTRY`, and `none` before broadening the query.",
    "representative_cases": [
      "authlib__authlib::CVE-2026-28802"
    ],
    "reviewer_notes": "Keep this boundary separate from generic token validation. The reusable mechanism is the unsafe default JWT algorithm policy, especially the implicit availability of unsigned `none`, not arbitrary missing claim validation.",
    "safe_fix_semantics": "Construct the default JWT helper with a signed-algorithm allowlist that omits `none`, and create a narrowly scoped `JsonWebToken([\"none\"])` only in flows or tests that intentionally exercise unsecured JWT behavior. Encoding paths should instantiate `JsonWebToken([alg])` for the configured algorithm instead of relying on the all-algorithm default.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The default JWT helper is used to decode or encode identity-bearing JWT artifacts, including OAuth request objects and OIDC userinfo/id-token style responses. If `none` is available by default, callers that did not intentionally allow unsigned JWTs can accept or emit unsigned tokens in authentication or authorization flows.",
    "source_shape": "Authlib exposes a module-level JWT helper initialized as `JsonWebToken(list(JsonWebSignature.ALGORITHMS_REGISTRY.keys()))`, so the default helper inherits every registered JWS algorithm, including `none`. Downstream OIDC and OAuth helper code imports this default `jwt` object for request-object and userinfo token handling."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.