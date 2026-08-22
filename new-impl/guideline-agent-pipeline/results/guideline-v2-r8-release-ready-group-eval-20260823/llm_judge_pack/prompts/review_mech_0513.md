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

Guideline group payload:
{
  "case_examples": [
    {
      "anchor_examples": [
        {
          "end_line": 276,
          "file": "authlib/jose/rfc7515/jws.py",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 269,
          "symbol": ""
        },
        {
          "end_line": 759,
          "file": "authlib/jose/rfc7516/jwe.py",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 754,
          "symbol": ""
        },
        {
          "end_line": 273,
          "file": "authlib/jose/rfc7515/jws.py",
          "span_kind": "file_region",
          "start_line": 271,
          "symbol": "authlib/jose/rfc7515/jws.py:269-276.center_window_3"
        },
        {
          "end_line": 274,
          "file": "authlib/jose/rfc7515/jws.py",
          "span_kind": "file_region",
          "start_line": 270,
          "symbol": "authlib/jose/rfc7515/jws.py:269-276.center_window_5"
        },
        {
          "end_line": 275,
          "file": "authlib/jose/rfc7515/jws.py",
          "span_kind": "file_region",
          "start_line": 269,
          "symbol": "authlib/jose/rfc7515/jws.py:269-276.center_window_7"
        }
      ],
      "case_id": "case::2a94e25c3e1b3ff99cfc",
      "cve_ids": [
        "CVE-2026-27962"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "authlib__authlib::CVE-2026-27962",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 9,
          "file": "dispatcher/src/main/java/com/manydesigns/portofino/dispatcher/security/jwt/JWTRealm.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 61,
          "file": "dispatcher/src/main/java/com/manydesigns/portofino/dispatcher/security/jwt/JWTRealm.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 53,
          "symbol": ""
        },
        {
          "end_line": 70,
          "file": "dispatcher/src/main/java/com/manydesigns/portofino/dispatcher/security/jwt/JWTRealm.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 64,
          "symbol": ""
        }
      ],
      "case_id": "case::742e324b35308069594c",
      "cve_ids": [
        "CVE-2021-29451"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "manydesigns__portofino::CVE-2021-29451",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 42,
          "file": "utility/src/main/java/eu/nimble/utility/validation/ValidationUtil.java",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 36,
          "symbol": ""
        },
        {
          "end_line": 43,
          "file": "utility/src/main/java/eu/nimble/utility/validation/ValidationUtil.java",
          "span_kind": "method",
          "start_line": 34,
          "symbol": "validateToken"
        }
      ],
      "case_id": "case::c1018ff374954fac09b3",
      "cve_ids": [
        "CVE-2021-32631"
      ],
      "cwe_ids": [
        "CWE-290"
      ],
      "identity_key": "nimble-platform__common::CVE-2021-32631",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "ValidationUtil.java文件39行使用parse方法解析JWT时不会验证JWT签名，攻击者可以利用该方法构造伪造的JWT，从而绕过认证 修改后函数 ''' return Jwts.parser().setSigningKey(publicKey).parseJws(token.replace(\"Bearer \", \"\")).getBody(); //VULNERABILITY 不使用parse方法（不强制验证JWT签名），更改使用安全的parseJws方法（强制验证JWT签名） '''",
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": "Common is a package of common modules that can be accessed by NIMBLE services. Common before commit number 3b96cb0293d3443b870351945f41d7d55cb34b53 did not properly verify the signature of JSON Web Tokens. This allows someone to forge a valid JWT. Being able to forge JWTs may lead to authentication bypasses. Commit number 3b96cb0293d3443b870351945f41d7d55cb34b53 contains a patch for the issue. As a workaround, one may use the parseClaimsJws method to correctly verify the signature of a JWT."
    },
    {
      "anchor_examples": [
        {
          "end_line": 145,
          "file": "pac4j-oidc/src/main/java/org/pac4j/oidc/config/OidcConfiguration.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 140,
          "symbol": ""
        },
        {
          "end_line": 491,
          "file": "pac4j-oidc/src/main/java/org/pac4j/oidc/config/OidcConfiguration.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 486,
          "symbol": ""
        },
        {
          "end_line": 500,
          "file": "pac4j-oidc/src/main/java/org/pac4j/oidc/config/OidcConfiguration.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 495,
          "symbol": ""
        }
      ],
      "case_id": "case::3c05a13101c9caaeb428",
      "cve_ids": [
        "CVE-2021-44878"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "pac4j__pac4j::CVE-2021-44878",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster contains vulnerabilities that allow attackers to bypass authentication or authorization by exploiting missing validation checks, timing side-channels, insecure cryptographic operations, and session management flaws. The issues include failure to verify user existence, token validity, claim correctness, and the use of non-constant-time comparisons, weak PRNGs, and untrusted algorithm handling.",
  "guideline_group_key": "cluster_0089__pending_mech_cluster_89_jwt_signature_verification_and_algorithm_handling_failures",
  "guideline_id": "review_mech_0513",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 7 historical CVE example(s), not as a project-specific signature. A safe implementation should Always verify signature using a method that validates the algorithm against a whitelist, reject empty/unsupported algorithms..",
  "judge_selection_reason": "evidence_limited",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_89_jwt_signature_verification_and_algorithm_handling_failures",
    "name": "JWT signature verification and algorithm handling failures"
  },
  "structural_sanity": {
    "assigned_case_count": 4,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.75,
    "flags": [
      "pending_review",
      "review_only"
    ],
    "metadata_cve_count": 4,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 7
  }
}