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
    "boundary_label": "candidate_boundary_01_jjwt_parse_without_jws_verification",
    "boundary_text": "JJWT parser API misuse: attacker-controlled bearer, session, or authentication tokens are parsed with Jwts.parser().setSigningKey(...).parse(...) or another generic JWT parse API whose return path does not force a signed JWS validation step before authentication claims are trusted. Report code paths where parsed claims or principals are accepted for authentication or authorization without using parseJws, parseClaimsJws, or an equivalent signature-verifying API on the same token path.",
    "evidence_refs": [
      {
        "identity_key": "nimble-platform__common::CVE-2021-32631",
        "source_evidence": "Patch commit 12197a755bd524559bf4e16475595a2c6fcd34db changes utility/src/main/java/eu/nimble/utility/validation/ValidationUtil.java:36-42 from Jwts.parser().setSigningKey(publicKey).parse(token.replace(\"Bearer \", \"\")).getBody() to parseJws(...).getBody(). The dataset description states that Common did not properly verify JWT signatures and that forged JWTs could bypass authentication."
      },
      {
        "identity_key": "manydesigns__portofino::CVE-2021-29451",
        "source_evidence": "Patch commit 8c754a0ad234555e813dcbf9e57d637f9f23d8fb changes dispatcher/src/main/java/com/manydesigns/portofino/dispatcher/security/jwt/JWTRealm.java:51-58 from Jwt jwt = Jwts.parser().setSigningKey(key).parse((String) token.getPrincipal()) to Jws<Claims> jwt = ...parseClaimsJws((String) token.getPrincipal()), then uses getPrincipal(jwt) for SimpleAuthenticationInfo."
      },
      {
        "identity_key": "manydesigns__portofino::CVE-2021-29451",
        "source_evidence": "The same patch changes portofino-core/src/main/java/com/manydesigns/portofino/shiro/AbstractPortofinoRealm.java:97-108 from generic Jwt parse(token.getPrincipal()) to Jws<Claims> parseClaimsJws(token.getPrincipal()), and the changelog says the vulnerability may have allowed access with forged tokens."
      }
    ],
    "exploit_precondition": "An attacker can submit a crafted JWT to the affected authentication or authorization endpoint, and the application trusts claims or principal data returned from the generic parse path.",
    "guideline_id": "review_mech_0513",
    "mechanism_id": "mech_jjwt_parse_without_jws_signature_verification",
    "mechanism_name": "JJWT parser API accepts JWT without forcing JWS signature verification",
    "missing_guard": "The vulnerable code uses the generic parse(...) API instead of parseJws(...) or parseClaimsJws(...), so signature verification is not forced before claims/principal extraction on the same authentication path.",
    "rationale": "Two independent Java patches replace generic JJWT parse calls on authentication paths with signed-JWS parsing APIs, and both effects trust parsed claims or principals for authentication. This supports a reusable but narrow source-reviewed mechanism.",
    "recall_follow_up": "After promoting this boundary into recall-consumed text, rerun same-identity recall on nimble-platform__common::CVE-2021-32631 and manydesigns__portofino::CVE-2021-29451. If recall misses, inspect whether candidate windows include Jwts.parser, setSigningKey, parse, parseClaimsJws, and principal/Claims construction before changing the semantic boundary.",
    "representative_cases": [
      "nimble-platform__common::CVE-2021-32631",
      "manydesigns__portofino::CVE-2021-29451"
    ],
    "reviewer_notes": "This promoted boundary is specifically about JJWT generic parse accepting tokens before a signed-JWS validation API is required. It should stay separate from JOSE header-supplied key trust and OIDC none-algorithm acceptance because the source APIs, trust decisions, and fixes differ.",
    "safe_fix_semantics": "Use a JJWT API that requires a signed JWS and validates the signature with the configured key, such as parseJws or parseClaimsJws, before extracting claims or constructing the authenticated principal. The fix must replace the exact parser call used by the authentication path.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The parsed JWT body or claims are returned as authenticated Claims or converted into a principal and SimpleAuthenticationInfo. If the parser path accepts an unsigned or otherwise unverified token, forged claims can cross the authentication boundary.",
    "source_shape": "A Java authentication or token-validation component receives an attacker-controlled JWT string from a Bearer token or authentication principal and passes it to JJWT after setting an expected signing key."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.