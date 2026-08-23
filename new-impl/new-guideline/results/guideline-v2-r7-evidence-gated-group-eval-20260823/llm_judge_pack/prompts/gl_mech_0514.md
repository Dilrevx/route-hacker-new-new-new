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
          "end_line": 16,
          "file": "basic-auth/src/main/java/com/nexblocks/authguard/basic/BasicAuthProvider.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 7,
          "symbol": ""
        },
        {
          "end_line": 92,
          "file": "basic-auth/src/main/java/com/nexblocks/authguard/basic/BasicAuthProvider.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 86,
          "symbol": ""
        },
        {
          "end_line": 108,
          "file": "basic-auth/src/main/java/com/nexblocks/authguard/basic/BasicAuthProvider.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 103,
          "symbol": ""
        },
        {
          "end_line": 33,
          "file": "rest/src/main/java/com/nexblocks/authguard/rest/server/ServerMiddlewareHandlers.java",
          "span_kind": "method",
          "start_line": 19,
          "symbol": "configure"
        },
        {
          "end_line": 87,
          "file": "rest/src/main/java/com/nexblocks/authguard/rest/access/AuthorizationHandler.java",
          "span_kind": "method",
          "start_line": 20,
          "symbol": "AuthorizationHandler"
        }
      ],
      "case_id": "case::19855abb4c180af8e63c",
      "cve_ids": [
        "CVE-2021-45890"
      ],
      "cwe_ids": [
        "CWE-287"
      ],
      "identity_key": "authguard__authguard::CVE-2021-45890",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "BasicAuthProvider.java文件中86行verifyCredentialsAndGetAccount函数未检查credentials是不活跃的，导致可以使用被禁用的账户 进行认证 修改后函数 ''' final Optional<Exception> validationError = checkIdentifier(credentials.get(), username); if (validationError.isPresent()) { return Either.left(validationError.get()); } ''' ''' private Optional<Exception> checkIdentifier(final CredentialsBO credentials, final String identifier) { final Optional<UserIdentifierBO> matchedIdentifier = credentials.getIdentifiers() .stream() .filter(existin...",
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": "basic/BasicAuthProvider.java in AuthGuard before 0.9.0 allows authentication via an inactive identifier."
    },
    {
      "anchor_examples": [
        {
          "end_line": 61,
          "file": "booklore-api/src/main/java/com/adityachandel/booklore/config/security/filter/CoverJwtFilter.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 41,
          "symbol": ""
        },
        {
          "end_line": 9,
          "file": "booklore-api/src/main/java/com/adityachandel/booklore/controller/BookMediaController.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 1,
          "symbol": ""
        }
      ],
      "case_id": "case::2bec16694de480f65ea6",
      "cve_ids": [
        "CVE-2025-62614"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "booklore-app__booklore::CVE-2025-62614",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 50,
          "file": "taier-data-develop/src/main/java/com/dtstack/taier/develop/interceptor/LoginInterceptor.java",
          "span_kind": "phase21_016_review_entry_window",
          "start_line": 37,
          "symbol": "LoginInterceptor.preHandle"
        }
      ],
      "case_id": "case::02815318d0822853f850",
      "cve_ids": [
        "CVE-2026-11618"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dtstack__taier::CVE-2026-11618",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21.016 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 33,
          "file": "grassroot-integration/src/main/java/za/org/grassroot/integration/authentication/JwtService.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 21,
          "symbol": ""
        },
        {
          "end_line": 202,
          "file": "grassroot-integration/src/main/java/za/org/grassroot/integration/authentication/JwtServiceImpl.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 170,
          "symbol": ""
        },
        {
          "end_line": 337,
          "file": "grassroot-webapp/src/main/java/za/org/grassroot/webapp/controller/rest/authentication/AuthenticationController.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 318,
          "symbol": ""
        }
      ],
      "case_id": "case::a4477d5937bb3c7c82c2",
      "cve_ids": [
        "CVE-2021-29455"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "grassrootza__grassroot-platform::CVE-2021-29455",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 134,
          "file": "jans-config-api/server/src/main/java/io/jans/configapi/security/service/OpenIdAuthorizationService.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 128,
          "symbol": ""
        },
        {
          "end_line": 367,
          "file": "jans-config-api/server/src/main/java/io/jans/configapi/util/AuthUtil.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 359,
          "symbol": ""
        }
      ],
      "case_id": "case::f65d4a7f5e6f5ace78e5",
      "cve_ids": [
        "CVE-2025-53003"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "janssenproject__jans::CVE-2025-53003",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 23,
          "file": "framework/gateway/src/main/java/io/metersphere/gateway/controller/LoginController.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 17,
          "symbol": ""
        },
        {
          "end_line": 90,
          "file": "framework/gateway/src/main/java/io/metersphere/gateway/controller/LoginController.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 84,
          "symbol": ""
        },
        {
          "end_line": 9,
          "file": "framework/gateway/src/main/java/io/metersphere/gateway/service/LdapService.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 3,
          "symbol": ""
        }
      ],
      "case_id": "case::e29f073c9b37a2ef46e5",
      "cve_ids": [
        "CVE-2025-62604"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "metersphere__metersphere::CVE-2025-62604",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 116,
          "file": "modules/kernel/src/main/java/org/opencastproject/kernel/security/SecurityServiceSpringImpl.java",
          "span_kind": "phase21_009_review_entry_window",
          "start_line": 95,
          "symbol": "SecurityServiceSpringImpl.getUser"
        },
        {
          "end_line": 96,
          "file": "modules/kernel/src/main/java/org/opencastproject/kernel/security/AuthenticationSuccessHandler.java",
          "span_kind": "method",
          "start_line": 65,
          "symbol": "onAuthenticationSuccess"
        },
        {
          "end_line": 148,
          "file": "modules/kernel/src/main/java/org/opencastproject/kernel/security/SecurityServiceSpringImpl.java",
          "span_kind": "method",
          "start_line": 90,
          "symbol": "getUser"
        },
        {
          "end_line": 152,
          "file": "modules/kernel/src/main/java/org/opencastproject/kernel/security/SecurityServiceSpringImpl.java",
          "span_kind": "method",
          "start_line": 91,
          "symbol": "getUser"
        }
      ],
      "case_id": "case::7c3775bc6205a6372b2b",
      "cve_ids": [
        "CVE-2020-5206"
      ],
      "cwe_ids": [
        "CWE-287"
      ],
      "identity_key": "opencast__opencast::CVE-2020-5206",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "getUser在获取当前用户时，只检查了Authentication对象是否为null，没有判断是否为匿名认证，攻击者使用伪造的cookie访问端点时，虽然cookie验证失败会创建AnonymousAuthenticationToken，但代码仍会从cookie中提取用户名并创建对应的User对象，导致攻击者可以假冒任意用户（或管理员） ``` @Override public User getUser() throws IllegalStateException { Organization org = getOrganization(); if (org == null) throw new IllegalStateException(\"No organization is set in security context\"); User delegatedUser = delegatedUserHolder.get(); if (delegatedUser != null) { return delegatedUser; } Authentication auth = Se...",
        "Phase 21.009 materialized this label only after taking a Phase 21.007 source-acquisition work order, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": "In Opencast before 7.6 and 8.1, using a remember-me cookie with an arbitrary username can cause Opencast to assume proper authentication for that user even if the remember-me cookie was incorrect given that the attacked endpoint also allows anonymous access. This way, an attacker can, for example, fake a remember-me token, assume the identity of the global system administrator and request non-public content from the search service without ever providing any proper authentication. This problem is fixed in Opencast 7.6 and Opencast 8.1"
    }
  ],
  "cluster_summary": "This cluster contains vulnerabilities that allow attackers to bypass authentication or authorization by exploiting missing validation checks, timing side-channels, insecure cryptographic operations, and session management flaws. The issues include failure to verify user existence, token validity, claim correctness, and the use of non-constant-time comparisons, weak PRNGs, and untrusted algorithm handling.",
  "guideline_group_key": "cluster_0089__pending_mech_cluster_89_missing_validation_in_authentication_authorization_flows",
  "guideline_id": "gl_mech_0514",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 11 historical CVE example(s), not as a project-specific signature. A safe implementation should Add explicit validation checks for each missing condition, correct logical errors (e.g., OR→AND), and invalidate one-time tokens after use..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_89_missing_validation_in_authentication_authorization_flows",
    "name": "Missing validation in authentication/authorization flows"
  },
  "structural_sanity": {
    "assigned_case_count": 7,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.7143,
    "flags": [
      "mixed_hcvr",
      "pending_review"
    ],
    "metadata_cve_count": 7,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 0.5714,
    "source_cve_count": 11
  }
}