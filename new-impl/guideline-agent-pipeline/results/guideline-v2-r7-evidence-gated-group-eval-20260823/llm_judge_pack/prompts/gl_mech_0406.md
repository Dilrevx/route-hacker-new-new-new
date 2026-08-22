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
          "end_line": 1540,
          "file": "extensions/bluebubbles/src/monitor.ts",
          "span_kind": "phase21_030_review_entry_window",
          "start_line": 1528,
          "symbol": "handleBlueBubblesWebhookRequest local bypass"
        }
      ],
      "case_id": "case::87d20ab99d1ea4a996fa",
      "cve_ids": [
        "CVE-2026-8305"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "openclaw__openclaw::CVE-2026-8305",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21.030 materialized this label only after selecting a cached CVE intake backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 80,
          "file": "server-core/src/main/java/io/onedev/server/git/hookcallback/GitPreReceiveCallback.java",
          "span_kind": "phase21_013_review_entry_window",
          "start_line": 71,
          "symbol": "GitPreReceiveCallback"
        },
        {
          "end_line": 65,
          "file": "server-core/src/main/java/io/onedev/server/git/hookcallback/GitPostReceiveCallback.java",
          "span_kind": "phase21_013_review_entry_window",
          "start_line": 56,
          "symbol": "GitPostReceiveCallback"
        }
      ],
      "case_id": "case::536b126b1259e836189e",
      "cve_ids": [
        "CVE-2022-39205"
      ],
      "cwe_ids": [
        "CWE-287"
      ],
      "identity_key": "theonedev__onedev::CVE-2022-39205",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "GitPostReceiveCallback.java以及GitPreReceiveCallback.java文件中doPost函数IP来源的逻辑依赖于请求头X-Forwarded-For，攻击者可以伪造请求头，伪装成从本地访问，从而绕过认证 修改前代码： ''' String clientIp = request.getHeader(\"X-Forwarded-For\"); if (clientIp == null) clientIp = request.getRemoteAddr(); if (!InetAddress.getByName(clientIp).isLoopbackAddress()) { response.sendError(HttpServletResponse.SC_FORBIDDEN, \"Git hook callbacks can only be accessed from localhost.\"); return; } List<String> fields = StringUtils.splitAndTrim(request.getPathInfo(...",
        "Phase 21.013 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": "Onedev is an open source, self-hosted Git Server with CI/CD and Kanban. In versions of Onedev prior to 7.3.0 unauthenticated users can take over a OneDev instance if there is no properly configured reverse proxy. The /git-prereceive-callback endpoint is used by the pre-receive git hook on the server to check for branch protections during a push event. It is only intended to be accessed from localhost, but the check relies on the X-Forwarded-For header. Invoking this endpoint leads to the execution of one of various git commands. The environment variables of this command execution can be controlled via query parameters. This allows attackers to write to arbitrary files, which can in turn l..."
    }
  ],
  "cluster_summary": "This cluster contains 39 CVEs that expose authentication and authorization weaknesses in webhook and API endpoints. The vulnerabilities arise from missing or insufficient validation of tokens and secrets, over-reliance on untrusted headers or loopback IPs for authentication bypass, timing side-channels from non-constant-time comparisons, missing rate limiting on authentication attempts, resource exhaustion due to body parsing before authentication, insufficient replay protection and deduplication, missing control flow termination, ambiguous routing logic, fail-open defaults on missing security configuration, cached secrets not refreshed after rotation, and missing pre-authentication concurrency throttling.",
  "guideline_group_key": "cluster_0074__pending_mech_cluster_74_authentication_bypass_via_untrusted_headers_or_loopback_trust",
  "guideline_id": "gl_mech_0406",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should Remove unconditional trust in headers and loopback IPs. Use configured public URLs, enforce authentication for all requests, or validate headers against a configured allowlist of trusted proxies..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_74_authentication_bypass_via_untrusted_headers_or_loopback_trust",
    "name": "Authentication Bypass via Untrusted Headers or Loopback Trust"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "CWE-287",
    "cwe_purity": 0.5,
    "flags": [
      "mixed_cwe",
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 2
  }
}