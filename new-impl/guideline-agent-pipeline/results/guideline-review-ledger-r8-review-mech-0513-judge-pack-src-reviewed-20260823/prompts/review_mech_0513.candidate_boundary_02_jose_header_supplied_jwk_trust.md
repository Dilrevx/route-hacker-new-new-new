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
    "boundary_label": "candidate_boundary_02_jose_header_supplied_jwk_trust",
    "boundary_text": "JOSE header-supplied JWK trust: JWS or JWE processing falls back to a `jwk` value carried inside the untrusted token header when the caller does not provide a key. Report code paths where token-controlled header key material is passed to algorithm.prepare_key or an equivalent verification/decryption key preparation step before the token's authenticity or key policy has been established.",
    "evidence_refs": [
      {
        "identity_key": "authlib__authlib::CVE-2026-27962",
        "source_evidence": "Patch commit a5d4b2d4c9e46bfa11c82f85fdc2bcc0b50ae681 has subject `fix(jose): do not use header's jwk automatically`. It removes `elif key is None and \"jwk\" in header: key = header[\"jwk\"]` from authlib/jose/rfc7515/jws.py:_prepare_algorithm_key before algorithm.prepare_key(key)."
      },
      {
        "identity_key": "authlib__authlib::CVE-2026-27962",
        "source_evidence": "The same patch removes the identical fallback from authlib/jose/rfc7516/jwe.py:prepare_key, confirming the common mechanism is token-header key trust in JOSE key preparation rather than JJWT parser API misuse."
      }
    ],
    "exploit_precondition": "An attacker can submit a JOSE token containing a `jwk` header to an application that invokes Authlib verification/decryption with no explicit key or with a key callback path that permits this fallback.",
    "guideline_id": "review_mech_0513",
    "mechanism_id": "mech_jose_header_supplied_jwk_key_trust",
    "mechanism_name": "JOSE token header-supplied JWK trusted as verification or decryption key",
    "missing_guard": "The vulnerable fallback accepts token header `jwk` automatically when key is None, without requiring application-provided key material, configured trust policy, or explicit opt-in to header-provided keys.",
    "rationale": "The patch directly removes automatic trust in a token-supplied JWK on both JWS and JWE key-preparation paths. The evidence supports a narrow single-project but reusable JOSE mechanism.",
    "recall_follow_up": "After a sidecar change, rerun same-identity recall for authlib__authlib::CVE-2026-27962 and inspect whether candidate slicing captures `_prepare_algorithm_key`, `prepare_key`, `header[\"jwk\"]`, and `algorithm.prepare_key` before changing the query text.",
    "representative_cases": [
      "authlib__authlib::CVE-2026-27962"
    ],
    "reviewer_notes": "This is a JOSE key-selection trust-boundary mechanism. It belongs in the broader authentication-token validation family, but should not be merged with JJWT parse/parseClaimsJws misuse or OIDC `none` algorithm handling.",
    "safe_fix_semantics": "Remove the automatic header[\"jwk\"] fallback from JWS/JWE key preparation. Applications that want embedded keys must implement an explicit trusted-key selection policy outside the generic parser path.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The header-provided JWK is passed into algorithm.prepare_key and can become the key used for JWS verification or JWE decryption/key handling. Trusting key material supplied by the same token undermines the authentication or confidentiality boundary.",
    "source_shape": "A Python JOSE library prepares keys for JWS or JWE processing. The protected header is attacker-controlled token metadata, and vulnerable code reads header[\"jwk\"] when no caller key is supplied."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.