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
          "end_line": 12,
          "file": "connector/pom.xml",
          "span_kind": "hunk",
          "start_line": 6,
          "symbol": ""
        },
        {
          "end_line": 33,
          "file": "connector/pom.xml",
          "span_kind": "hunk",
          "start_line": 21,
          "symbol": ""
        },
        {
          "end_line": 44,
          "file": "connector/src/main/java/org/geysermc/connector/network/translators/bedrock/BedrockContainerCloseTranslator.java",
          "span_kind": "hunk",
          "start_line": 38,
          "symbol": ""
        },
        {
          "end_line": 48,
          "file": "connector/src/main/java/org/geysermc/connector/network/translators/bedrock/BedrockEntityPickRequestTranslator.java",
          "span_kind": "hunk",
          "start_line": 42,
          "symbol": ""
        },
        {
          "end_line": 48,
          "file": "connector/src/main/java/org/geysermc/connector/network/translators/java/entity/spawn/JavaSpawnLivingEntityTranslator.java",
          "span_kind": "hunk",
          "start_line": 42,
          "symbol": ""
        }
      ],
      "case_id": "case::8540ebf58583e0393d85",
      "cve_ids": [
        "CVE-2021-39177"
      ],
      "cwe_ids": [
        "CWE-287"
      ],
      "identity_key": "geysermc__geyser::CVE-2021-39177",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [
        "LoginEncryptionUtils.java64行validateChainData函数中对JWT签名验证不够充分，修改后强制使用x5u并用其生成公钥，并且检查链的连续性，防止插入数据包 密码学误用 该漏洞在14.2版本中修复，有多个文件将版本从14.1改为14.2 ''' private static boolean validateChainData(JsonNode data) throws Exception { if (data.size() != 3) { return false; } ECPublicKey lastKey = null; boolean validChain = false; for (JsonNode node : data) { JWSObject jwt = JWSObject.parse(node.asText()); // x509 cert is expected in every claim URI x5u = jwt.getHeader().getX509CertURL(); if (x5u == null) { retur..."
      ],
      "vulnerability_description": "Geyser is a bridge between Minecraft: Bedrock Edition and Minecraft: Java Edition. Versions of Geyser prior to 1.4.2-SNAPSHOT allow anyone that can connect to the server to forge a LoginPacket with manipulated JWT token allowing impersonation as any user. Version 1.4.2-SNAPSHOT contains a patch for the issue. There are no known workarounds aside from upgrading."
    },
    {
      "anchor_examples": [
        {
          "end_line": 26,
          "file": "google-oauth-client/src/main/java/com/google/api/client/auth/oauth2/AuthorizationCodeFlow.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 17,
          "symbol": ""
        },
        {
          "end_line": 36,
          "file": "google-oauth-client/src/main/java/com/google/api/client/auth/oauth2/AuthorizationCodeFlow.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 29,
          "symbol": ""
        },
        {
          "end_line": 90,
          "file": "google-oauth-client/src/main/java/com/google/api/client/auth/oauth2/AuthorizationCodeFlow.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 85,
          "symbol": ""
        },
        {
          "end_line": 187,
          "file": "google-oauth-client/src/main/java/com/google/api/client/auth/oauth2/AuthorizationCodeFlow.java",
          "span_kind": "method",
          "start_line": 184,
          "symbol": "newAuthorizationUrl"
        },
        {
          "end_line": 99,
          "file": "samples/keycloak-pkce-cmdline-sample/src/main/java/com/google/api/services/samples/keycloak/cmdline/PKCESample.java",
          "span_kind": "method",
          "start_line": 85,
          "symbol": "main"
        }
      ],
      "case_id": "case::fdeaffffe18a5bff0642",
      "cve_ids": [
        "CVE-2020-7692"
      ],
      "cwe_ids": [
        "CWE-863"
      ],
      "identity_key": "googleapis__google-oauth-java-client::CVE-2020-7692",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "AuthorizationCodeFlow在实现OAuth2.0授权码时未实现PKCE，授权码可能被恶意应用拦截并冒用。原代码中newAuthorizationUrl方法生成授权请求时不包含code_challenge参数，newTokenRequest请求令牌时也不包含code_verifier，使得攻击者可以在原生应用环境中窃取授权码后直接换取访问令牌 ``` public AuthorizationCodeRequestUrl newAuthorizationUrl() { // VULNERABILITY: 直接返回授权URL，没有添加任何PKCE参数 // 缺少code_challenge和code_challenge_method // 授权码可以被任何拿到它的客户端使用 return new AuthorizationCodeRequestUrl(authorizationServerEncodedUrl, clientId).setScopes( scopes); } ``` ``` public AuthorizationCodeTokenRequest new...",
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": "PKCE support is not implemented in accordance with the RFC for OAuth 2.0 for Native Apps. Without the use of PKCE, the authorization code returned by an authorization server is not enough to guarantee that the client that issued the initial authorization request is the one that will be authorized. An attacker is able to obtain the authorization code using a malicious app on the client-side and use it to gain authorization to the protected resource. This affects the package com.google.oauth-client:google-oauth-client before 1.31.0."
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
          "end_line": 1597,
          "file": "openam-federation/openam-federation-library/src/main/java/com/sun/identity/saml/common/SAMLUtils.java",
          "span_kind": "hunk",
          "start_line": 1585,
          "symbol": ""
        },
        {
          "end_line": 956,
          "file": "openam-federation/openam-federation-library/src/main/java/com/sun/identity/saml/common/SAMLUtils.java",
          "span_kind": "hunk",
          "start_line": 951,
          "symbol": ""
        }
      ],
      "case_id": "case::8e4be3273acb6178ef03",
      "cve_ids": [
        "CVE-2023-37471"
      ],
      "cwe_ids": [
        "CWE-287"
      ],
      "identity_key": "openidentityplatform__openam::CVE-2023-37471",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [
        "仅在存在签名时 (isSigned) 做了校验，攻击者构造一个不含签名的 SAML Response 就能绕过验证。 修复方法：在进到 processResponse 前，在 verifyResponse 函数里对 isSigned 做了判断， 没有签名就直接进入错误分支退出 调用链为 doPost -> verifyResponse, doPost -> processResponse -> verifySignature ``` diff // VULNERABILITY: only verify if the response is signed // FIX: 在 verifyResponse 里增加对 isSigned 的判断，没有签名直接返回 false public static boolean verifyResponse(Response response, String requestUrl, HttpServletRequest request) { + if(!response.isSigned()) { + debug.message(\"verifyRe..."
      ],
      "vulnerability_description": "Open Access Management (OpenAM) is an access management solution that includes Authentication, SSO, Authorization, Federation, Entitlements and Web Services Security. OpenAM up to version 14.7.2 does not properly validate the signature of SAML responses received as part of the SAMLv1.x Single Sign-On process. Attackers can use this fact to impersonate any OpenAM user, including the administrator, by sending a specially crafted SAML response to the SAMLPOSTProfileServlet servlet. This problem has been patched in OpenAM 14.7.3-SNAPSHOT and later. User unable to upgrade should comment servlet `SAMLPOSTProfileServlet` from their pom file. See the linked GHSA for details."
    }
  ],
  "cluster_summary": "A collection of authentication and authorization vulnerabilities where tokens or credentials are not properly validated, either cryptographically, temporally, or through binding checks, leading to bypass, impersonation, or unauthorized access.",
  "guideline_group_key": "cluster_0023__mech_missing_authentication_before_privileged_action",
  "guideline_id": "gl_mech_0129",
  "guideline_text": "Trace externally reachable requests, RPC messages, management calls, or background command triggers into privileged commands, administrative state changes, credential operations, or protected data access. Report code paths where caller identity is not established before the privileged action begins. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 15 historical CVE example(s), not as a project-specific signature. A safe implementation should require a validated session, principal, token, or authentication filter before any privileged effect.",
  "mechanism": {
    "family": "authentication",
    "mechanism_id": "mech_missing_authentication_before_privileged_action",
    "name": "missing authentication before privileged action"
  },
  "structural_sanity": {
    "assigned_case_count": 9,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.5556,
    "flags": [
      "mixed_hcvr",
      "mixed_cwe"
    ],
    "metadata_cve_count": 9,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 0.6667,
    "source_cve_count": 15
  }
}