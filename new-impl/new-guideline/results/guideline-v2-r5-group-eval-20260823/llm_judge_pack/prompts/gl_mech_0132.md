You are judging a reusable security-audit guideline group.

Evaluate whether the guideline accurately describes a coherent vulnerability mechanism shared by the listed cases.
Do not evaluate embedding recall, rank, or whether known anchors were hit.
Do not require all cases to share the same CWE or dataset label; those labels are only weak context.
Prefer mechanism-level judgments: source shape, sink shape, missing guard, exploit precondition, and safe fix.

Return JSON only with this schema:
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

Guideline group payload:
{
  "case_examples": [
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
  "cluster_summary": "A collection of authentication and authorization vulnerabilities where tokens or credentials are not properly validated, either cryptographically, temporally, or through binding checks, leading to bypass, impersonation, or unauthorized access.",
  "guideline_group_key": "cluster_0023__pending_mech_cluster_23_missing_cryptographic_token_verification",
  "guideline_id": "gl_mech_0132",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 3 historical CVE example(s), not as a project-specific signature. A safe implementation should Add mandatory cryptographic verification (signature verification, proof-of-possession, or decryption) before accepting token claims..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_23_missing_cryptographic_token_verification",
    "name": "Missing cryptographic token verification"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "CWE-290",
    "cwe_purity": 0.5,
    "flags": [
      "mixed_cwe",
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 3
  }
}