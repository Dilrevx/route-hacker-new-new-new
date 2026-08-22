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
          "end_line": 205,
          "file": "security-oauth2/src/main/java/io/micronaut/security/oauth2/client/IdTokenClaimsValidator.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 199,
          "symbol": ""
        }
      ],
      "case_id": "case::79ee6c80bf8b90d31dea",
      "cve_ids": [
        "CVE-2023-36820"
      ],
      "cwe_ids": [
        "CWE-284"
      ],
      "identity_key": "micronaut-projects__micronaut-security::CVE-2023-36820",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "在校验 issuer, audience 和 azp 时，存在逻辑缺陷，导致当同一 issuer 下存在多个客户端时，跳过了对 clientId 和 azp 的校验，存在未授权访问风险。 ```java issuer.equalsIgnoreCase(iss) || <--- 错误的逻辑操作符，应为 && audiences.contains(clientId) && validateAzp(claims, clientId, audiences); ``` 当用户设置 `micronaut.security.authentication` 为 `idtoken` 时，校验不符合 openID 文档给出的流程要求，没有验证 aud https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation > Clients MUST validate the ID Token in the Token Response in the following manner: ... > 1.2. The Issuer...",
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": "Micronaut Security is a security solution for applications. Prior to versions 3.1.2, 3.2.4, 3.3.2, 3.4.3, 3.5.3, 3.6.6, 3.7.4, 3.8.4, 3.9.6, 3.10.2, and 3.11.1, IdTokenClaimsValidator skips `aud` claim validation if token is issued by same identity issuer/provider. Any OIDC setup using Micronaut where multiple OIDC applications exists for the same issuer but token auth are not meant to be shared. This issue has been patched in versions 3.1.2, 3.2.4, 3.3.2, 3.4.3, 3.5.3, 3.6.6, 3.7.4, 3.8.4, 3.9.6, 3.10.2, and 3.11.1."
    },
    {
      "anchor_examples": [
        {
          "end_line": 173,
          "file": "keystone/contrib/ec2/core.py",
          "span_kind": "hunk",
          "start_line": 168,
          "symbol": ""
        },
        {
          "end_line": 192,
          "file": "keystone/contrib/ec2/core.py",
          "span_kind": "hunk",
          "start_line": 180,
          "symbol": ""
        }
      ],
      "case_id": "case::624604561579bfb486ae",
      "cve_ids": [
        "CVE-2012-5571"
      ],
      "cwe_ids": [
        "CWE-255"
      ],
      "identity_key": "openstack__keystone::CVE-2012-5571",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster contains vulnerabilities that allow attackers to bypass authentication or authorization by exploiting missing validation checks, timing side-channels, insecure cryptographic operations, and session management flaws. The issues include failure to verify user existence, token validity, claim correctness, and the use of non-constant-time comparisons, weak PRNGs, and untrusted algorithm handling.",
  "guideline_group_key": "cluster_0089__mech_authentication_artifact_incomplete_validation",
  "guideline_id": "gl_mech_0507",
  "guideline_text": "Trace externally supplied authentication artifacts such as JWTs, SAML responses, OAuth authorization codes, bearer tokens, session cookies, or client credentials into session creation, identity binding, privilege assignment, protected API access, or credential exchange decisions. Report code paths where signature, issuer, audience, expiry, nonce, binding, proof-of-possession, or protocol state validation is incomplete before accepting the identity. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 3 historical CVE example(s), not as a project-specific signature. A safe implementation should validate all required cryptographic and protocol fields before creating a principal or granting access, and bind the artifact to the intended client, audience, and session.",
  "mechanism": {
    "family": "authentication",
    "mechanism_id": "mech_authentication_artifact_incomplete_validation",
    "name": "authentication artifact accepted without complete validation"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "CWE-255",
    "cwe_purity": 0.5,
    "flags": [
      "mixed_hcvr",
      "mixed_cwe"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 3
  }
}