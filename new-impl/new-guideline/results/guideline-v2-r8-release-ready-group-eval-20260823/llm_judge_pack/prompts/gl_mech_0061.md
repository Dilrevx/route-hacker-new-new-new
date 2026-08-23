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
          "end_line": 200,
          "file": "modules/login/jsx/loginIndex.js",
          "span_kind": "phase15_2_review_entry_window",
          "start_line": 121,
          "symbol": "Login.handleSubmit redirect after auth"
        },
        {
          "end_line": 155,
          "file": "modules/login/jsx/loginIndex.js",
          "span_kind": "file_region",
          "start_line": 149,
          "symbol": "Login.handleSubmit redirect origin check"
        },
        {
          "end_line": 153,
          "file": "modules/login/jsx/loginIndex.js",
          "span_kind": "file_region",
          "start_line": 151,
          "symbol": "Login.handleSubmit redirect after auth.center_window_3"
        },
        {
          "end_line": 154,
          "file": "modules/login/jsx/loginIndex.js",
          "span_kind": "file_region",
          "start_line": 150,
          "symbol": "Login.handleSubmit redirect after auth.center_window_5"
        },
        {
          "end_line": 157,
          "file": "modules/login/jsx/loginIndex.js",
          "span_kind": "file_region",
          "start_line": 147,
          "symbol": "Login.handleSubmit redirect after auth.center_window_11"
        }
      ],
      "case_id": "case::ee1ad1539d178d966858",
      "cve_ids": [
        "CVE-2026-39985"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "aces__loris::CVE-2026-39985",
      "primary_hcvr_type": "open_redirect",
      "trace_evidence": [
        "After successful login, the old client assigns this.props.redirect directly to window.location.href when present. The patch parses the URL relative to window.location.origin and only navigates when the parsed origin matches."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 44,
          "file": "src/helpers.ts",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 31,
          "symbol": ""
        },
        {
          "end_line": 74,
          "file": "src/helpers.ts",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 58,
          "symbol": ""
        },
        {
          "end_line": 29,
          "file": "src/redirect.ts",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 24,
          "symbol": ""
        }
      ],
      "case_id": "case::92f8fbd1267c5b2b0909",
      "cve_ids": [
        "CVE-2026-40255"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "adonisjs__http-server::CVE-2026-40255",
      "primary_hcvr_type": "open_redirect",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 126,
          "file": "src/main/java/co/yiiu/pybbs/controller/front/IndexController.java",
          "span_kind": "function",
          "start_line": 118,
          "symbol": "changeLanguage"
        },
        {
          "end_line": 149,
          "file": "src/main/java/co/yiiu/pybbs/controller/front/IndexController.java",
          "span_kind": "function",
          "start_line": 130,
          "symbol": "active"
        },
        {
          "end_line": 120,
          "file": "src/main/java/co/yiiu/pybbs/controller/front/IndexController.java",
          "span_kind": "sliding_window",
          "start_line": 41,
          "symbol": "changeLanguage"
        },
        {
          "end_line": 154,
          "file": "src/main/java/co/yiiu/pybbs/controller/front/IndexController.java",
          "span_kind": "sliding_window",
          "start_line": 81,
          "symbol": "changeLanguage"
        },
        {
          "end_line": 126,
          "file": "src/main/java/co/yiiu/pybbs/controller/front/IndexController.java",
          "span_kind": "file_region",
          "start_line": 124,
          "symbol": "changeLanguage.center_window_3"
        }
      ],
      "case_id": "case::730ec944f89f3d8416fa",
      "cve_ids": [
        "CVE-2025-8813"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "atjiu__pybbs::CVE-2025-8813",
      "primary_hcvr_type": "open_redirect",
      "trace_evidence": [
        "Open redirect review-entry: inspect changeLanguage, where request.getHeader(\"referer\") is stored in referer and later passed to redirect(referer) when non-empty. The review question is whether redirect destinations derived from request headers are restricted to trusted same-origin or explicit allowlisted targets before redirecting."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 80,
          "file": "assets/vue/composables/auth/login.js",
          "span_kind": "sliding_window",
          "start_line": 1,
          "symbol": "normalizeRedirectUrl"
        },
        {
          "end_line": 120,
          "file": "assets/vue/composables/auth/login.js",
          "span_kind": "sliding_window",
          "start_line": 41,
          "symbol": "normalizeRedirectUrl"
        },
        {
          "end_line": 200,
          "file": "assets/vue/composables/auth/login.js",
          "span_kind": "sliding_window",
          "start_line": 121,
          "symbol": "login backend redirect sinks"
        },
        {
          "end_line": 160,
          "file": "assets/vue/composables/auth/login.js",
          "span_kind": "sliding_window",
          "start_line": 81,
          "symbol": "login payload returnUrl"
        },
        {
          "end_line": 64,
          "file": "assets/vue/composables/auth/login.js",
          "span_kind": "file_region",
          "start_line": 62,
          "symbol": "normalizeRedirectUrl.center_window_3"
        }
      ],
      "case_id": "case::5dcd4ecce1d83afa186d",
      "cve_ids": [
        "CVE-2025-66447"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "chamilo__chamilo-lms::CVE-2025-66447",
      "primary_hcvr_type": "open_redirect",
      "trace_evidence": [
        "normalizeRedirectUrl is the fixed-side policy window for redirect query parameters: relative path normalization, protocol validation, and same-origin checks. It is retained as the guard review entry.",
        "Several backend-provided responseData.redirect branches assign directly to window.location.href. These are concrete browser-navigation sinks that need same-origin or relative-target policy.",
        "The login flow reads route.query.redirect and passes it as returnUrl to the backend login payload. This is useful source/bridge context for the redirect target."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 43,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java",
          "span_kind": "function",
          "start_line": 20,
          "symbol": "doDSGet"
        },
        {
          "end_line": 51,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java",
          "span_kind": "function",
          "start_line": 45,
          "symbol": "doDSPost"
        },
        {
          "end_line": 64,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java",
          "span_kind": "sliding_window",
          "start_line": 1,
          "symbol": "ControlledVocabularyServlet.doDSGet"
        },
        {
          "end_line": 43,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java",
          "span_kind": "file_region",
          "start_line": 41,
          "symbol": "ControlledVocabularyServlet.doDSGet.center_window_3"
        },
        {
          "end_line": 44,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/servlet/ControlledVocabularyServlet.java",
          "span_kind": "file_region",
          "start_line": 40,
          "symbol": "ControlledVocabularyServlet.doDSGet.center_window_5"
        }
      ],
      "case_id": "case::1d9d9f23f699c9554109",
      "cve_ids": [
        "CVE-2022-31193"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dspace__dspace::CVE-2022-31193",
      "primary_hcvr_type": "open_redirect",
      "trace_evidence": [
        "doDSGet reads callerUrl directly from the HTTP request and passes it to response.sendRedirect after only storing ID/filter session state. The patch adds a request context-path check before redirecting, confirming this method as the open-redirect review entry."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 37,
          "file": "hsweb-authorization/hsweb-authorization-oauth2/src/main/java/org/hswebframework/web/oauth2/server/OAuth2Client.java",
          "span_kind": "function",
          "start_line": 33,
          "symbol": "validateRedirectUri"
        },
        {
          "end_line": 43,
          "file": "hsweb-authorization/hsweb-authorization-oauth2/src/main/java/org/hswebframework/web/oauth2/server/OAuth2Client.java",
          "span_kind": "function",
          "start_line": 35,
          "symbol": "validateSecret"
        },
        {
          "end_line": 45,
          "file": "hsweb-authorization/hsweb-authorization-oauth2/src/main/java/org/hswebframework/web/oauth2/server/OAuth2Client.java",
          "span_kind": "sliding_window",
          "start_line": 1,
          "symbol": "OAuth2Client.validateRedirectUri"
        },
        {
          "end_line": 80,
          "file": "hsweb-authorization/hsweb-authorization-oauth2/src/main/java/org/hswebframework/web/oauth2/server/web/OAuth2AuthorizeController.java",
          "span_kind": "function",
          "start_line": 54,
          "symbol": "authorizeByCode"
        },
        {
          "end_line": 80,
          "file": "hsweb-authorization/hsweb-authorization-oauth2/src/main/java/org/hswebframework/web/oauth2/server/web/OAuth2AuthorizeController.java",
          "span_kind": "function",
          "start_line": 55,
          "symbol": "authorizeByCode"
        }
      ],
      "case_id": "case::ef84654114bbfd86d136",
      "cve_ids": [
        "CVE-2026-11477"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hs-web__hsweb-framework::CVE-2026-11477",
      "primary_hcvr_type": "open_redirect",
      "trace_evidence": [
        "Redirect URI validation uses string startsWith against the registered redirectUrl, which is insufficient URI-origin validation and can accept attacker-controlled lookalike prefixes.",
        "Request redirect_uri is selected, passed through the weak validator, and later used to build the redirect response."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 209,
          "file": "services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java",
          "span_kind": "function",
          "start_line": 193,
          "symbol": "relativeToAbsoluteURI"
        },
        {
          "end_line": 209,
          "file": "services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java",
          "span_kind": "function",
          "start_line": 197,
          "symbol": "relativeToAbsoluteURI"
        },
        {
          "end_line": 228,
          "file": "services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java",
          "span_kind": "function",
          "start_line": 206,
          "symbol": "matchesRedirects"
        },
        {
          "end_line": 228,
          "file": "services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java",
          "span_kind": "function",
          "start_line": 207,
          "symbol": "matchesRedirects"
        },
        {
          "end_line": 228,
          "file": "services/src/main/java/org/keycloak/protocol/oidc/utils/RedirectUtils.java",
          "span_kind": "function",
          "start_line": 208,
          "symbol": "matchesRedirects"
        }
      ],
      "case_id": "case::15ee12b80b2260c66d7f",
      "cve_ids": [
        "CVE-2022-4361"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "keycloak__keycloak::CVE-2022-4361",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "Manual span repair confirms that the preserved old source places RedirectUtils.matchesRedirects at lines 232-249, not the candidate-pool extracted 206-228 span retained in Phase 21.092. The helper performs wildcard prefix/equality matching and returns only a boolean, so the caller cannot know which configured redirect pattern matched for non-http scheme validation. The patch changes the helper to return the matched pattern and rejects unsafe schemes unless explicitly allowed. This checkpoint...",
        "Manual repair confirms an open-redirect validation source contract: caller-controlled redirectUri is decoded, normalized, matched against wildcard-capable valid redirect patterns, and accepted without retaining the matched pattern for scheme validation. The patch returns the matched pattern from matchesRedirects and rejects non-http(s) schemes unless the matched pattern explicitly starts with that scheme. This checkpoint repairs metadata only; it does not add labels, run retrieval, or claim d..."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 34,
          "file": "publiccms-parent/publiccms/src/main/webapp/resource/plugins/pdfjs/viewer.html",
          "span_kind": "phase21_045_review_entry_window",
          "start_line": 29,
          "symbol": "pdfjs viewer inline redirect script"
        }
      ],
      "case_id": "case::c31d70ca3ec2787d14ca",
      "cve_ids": [
        "CVE-2025-7949"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "sanluan__publiccms::CVE-2025-7949",
      "primary_hcvr_type": "open_redirect",
      "trace_evidence": [
        "Only the compact PDF.js viewer redirect script is promoted. The source-ready intake's Java controller uploadIco anchors belong to a different fix hunk and are retained only as rejected provenance."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "The cluster comprises vulnerabilities where user-controlled input is used to construct URLs (redirect targets, server-side fetch URLs, navigation destinations, or URL query strings) without adequate validation or encoding. This leads to open redirect, server-side request forgery (SSRF), cross-site scripting (XSS), token leakage, and exposure of sensitive data. The root causes include missing host allowlist checks, incomplete URL parsing allowing bypasses, and failure to encode or filter sensitive data.",
  "guideline_group_key": "cluster_0037__mech_open_redirect_unsafe_uri_scheme",
  "guideline_id": "gl_mech_0061",
  "guideline_text": "Trace attacker-controlled redirect targets, callback URLs, return URLs, OAuth redirect_uri values, or browser navigation destinations into redirect responses, Location headers, OAuth/OIDC/SAML redirect validation, or browser-followed navigation targets. Report code paths where the redirect target is accepted without constraining the final scheme and destination to trusted browser-safe values. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 13 historical CVE example(s), not as a project-specific signature. A safe implementation should validate redirect targets with an explicit safe-scheme and destination allowlist after decoding and normalization.",
  "judge_selection_reason": "clean_control",
  "mechanism": {
    "family": "open_redirect",
    "mechanism_id": "mech_open_redirect_unsafe_uri_scheme",
    "name": "open redirect through unsafe URI scheme validation"
  },
  "structural_sanity": {
    "assigned_case_count": 9,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [],
    "metadata_cve_count": 9,
    "primary_hcvr_majority": "open_redirect",
    "primary_hcvr_purity": 0.8889,
    "source_cve_count": 13
  }
}