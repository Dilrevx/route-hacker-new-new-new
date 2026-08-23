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
          "end_line": 320,
          "file": "server.js",
          "span_kind": "sliding_window",
          "start_line": 241,
          "symbol": "app.all('/api/proxy') fetch sink"
        },
        {
          "end_line": 200,
          "file": "server.js",
          "span_kind": "sliding_window",
          "start_line": 121,
          "symbol": "app.all('/api/proxy') target URL entry"
        },
        {
          "end_line": 240,
          "file": "server.js",
          "span_kind": "sliding_window",
          "start_line": 161,
          "symbol": "app.all('/api/proxy') target URL entry"
        },
        {
          "end_line": 280,
          "file": "server.js",
          "span_kind": "sliding_window",
          "start_line": 201,
          "symbol": "app.all('/api/proxy') target URL entry"
        },
        {
          "end_line": 252,
          "file": "server.js",
          "span_kind": "file_region",
          "start_line": 250,
          "symbol": "app.all('/api/proxy') fetch sink.center_window_3"
        }
      ],
      "case_id": "case::a0c5bee6ed7b0f9b4f3e",
      "cve_ids": [
        "CVE-2026-5803"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "bigsk1__openai-realtime-ui::CVE-2026-5803",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "The old-side proxy appends extra query parameters to targetUrl and calls fetch(fullUrl, options). The fix replaces this with parseProxyTargetUrl and fetchWithSafeRedirects, confirming this span as the concrete URL-to-request SSRF sink.",
        "The proxy endpoint reads caller-controlled req.query.url as targetUrl and prepares outbound request options before any URL parsing, host/IP validation, or network-boundary policy exists."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 83,
          "file": "src/main/java/org/cbioportal/proxy/ProxyController.java",
          "span_kind": "phase21_009_review_entry_window",
          "start_line": 69,
          "symbol": "ProxyController.proxy"
        },
        {
          "end_line": 226,
          "file": "src/main/java/org/cbioportal/proxy/ProxyController.java",
          "span_kind": "phase21_009_review_entry_window",
          "start_line": 215,
          "symbol": "ProxyController.buildUri/exchangeData"
        }
      ],
      "case_id": "case::a6eb16caa665c9ea04fd",
      "cve_ids": [
        "CVE-2024-41668"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "cbioportal__cbioportal::CVE-2024-41668",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.009 materialized this label only after taking a Phase 21.007 source-acquisition work order, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 93,
          "file": "dhis-2/dhis-web/dhis-web-api/src/main/java/org/hisp/dhis/webapi/controller/SvgConversionController.java",
          "span_kind": "function",
          "start_line": 78,
          "symbol": "convertToPdf"
        },
        {
          "end_line": 93,
          "file": "dhis-2/dhis-web/dhis-web-api/src/main/java/org/hisp/dhis/webapi/controller/SvgConversionController.java",
          "span_kind": "function",
          "start_line": 81,
          "symbol": "convertToPdf"
        },
        {
          "end_line": 120,
          "file": "dhis-2/dhis-web/dhis-web-api/src/main/java/org/hisp/dhis/webapi/controller/SvgConversionController.java",
          "span_kind": "sliding_window",
          "start_line": 41,
          "symbol": "SvgConversionController.convertToPng"
        },
        {
          "end_line": 79,
          "file": "dhis-2/dhis-web/dhis-web-api/src/main/java/org/hisp/dhis/webapi/controller/SvgConversionController.java",
          "span_kind": "function",
          "start_line": 65,
          "symbol": "convertToPng"
        },
        {
          "end_line": 80,
          "file": "dhis-2/dhis-web/dhis-web-api/src/main/java/org/hisp/dhis/webapi/controller/SvgConversionController.java",
          "span_kind": "sliding_window",
          "start_line": 1,
          "symbol": "SvgConversionController.toPng"
        }
      ],
      "case_id": "case::df4e0ae63408eed73f6b",
      "cve_ids": [
        "CVE-2022-41949"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dhis2__dhis2-core::CVE-2022-41949",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "convertToPng sanitizes the SVG text and then calls Batik PNGTranscoder.transcode without disabling external resource loading. The fix adds SVGAbstractTranscoder.KEY_ALLOW_EXTERNAL_RESOURCES=false before transcode, confirming this block as the SSRF destination-policy sink.",
        "The /svg.png endpoint accepts caller-controlled SVG markup as a form parameter and forwards it to convertToPng. The CVE describes authenticated users causing DHIS2 to request external resources; the patch hardens the PNG transcoder path by disabling Batik external resources, so this endpoint is the review entry where untrusted SVG reaches the SSRF-capable renderer."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 539,
          "file": "nanobot/agent/tools/web.py",
          "span_kind": "phase21_028_review_entry_window",
          "start_line": 521,
          "symbol": "WebFetchTool._fetch_url image prefetch"
        }
      ],
      "case_id": "case::056e77dab763252af725",
      "cve_ids": [
        "CVE-2026-49138"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hkuds__nanobot::CVE-2026-49138",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.028 materialized this label only after selecting a cached CVE intake backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 372,
          "file": "app/api/endpoints/system.py",
          "span_kind": "phase21_019_review_entry_window",
          "start_line": 345,
          "symbol": "fetch_image"
        },
        {
          "end_line": 121,
          "file": "app/utils/security.py",
          "span_kind": "phase21_019_review_entry_window",
          "start_line": 73,
          "symbol": "SecurityUtils.is_safe_url"
        }
      ],
      "case_id": "case::4304aa618f7bd023526e",
      "cve_ids": [
        "CVE-2026-10107"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "jxxghp__moviepilot::CVE-2026-10107",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.019 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 230,
          "file": "packages/service/core/workflow/dispatch/child/runTool.ts",
          "span_kind": "phase21_028_review_entry_window",
          "start_line": 206,
          "symbol": "dispatchRunTool"
        },
        {
          "end_line": 86,
          "file": "packages/service/core/app/mcp.ts",
          "span_kind": "phase21_028_review_entry_window",
          "start_line": 16,
          "symbol": "MCPClient"
        },
        {
          "end_line": 210,
          "file": "packages/service/core/workflow/dispatch/ai/agent/sub/tool/index.ts",
          "span_kind": "phase21_028_review_entry_window",
          "start_line": 191,
          "symbol": "dispatchTool"
        }
      ],
      "case_id": "case::cc65cf2323206c99750c",
      "cve_ids": [
        "CVE-2026-44284"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "labring__fastgpt::CVE-2026-44284",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "The old runtime runTool path reused or created an MCPClient from a configured URL and then called the remote MCP tool without any internal/private-address gate. The patch adds assertMCPUrlNotInternal(url) before the cached client is used or created. This is review-entry retrieval ground truth only and does not claim dynamic exploit proof.",
        "The old FastGPT MCPClient stored a caller-provided MCP URL and used it to construct StreamableHTTPClientTransport or SSEClientTransport with new URL(this.url), without an internal/private-address policy at the transport boundary. The patch introduces assertMCPUrlNotInternal backed by isInternalAddress and PRIVATE_URL_TEXT. This is review-entry retrieval ground truth only and does not claim dynamic exploit proof.",
        "The old workflow dispatch path resolved an MCP tool URL from the toolset node and constructed MCPClient before calling toolCall, without rejecting internal/private MCP endpoints. The patch imports assertMCPUrlNotInternal and awaits it before constructing the client. This is review-entry retrieval ground truth only and does not claim dynamic exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 379,
          "file": "modules/kernel/src/main/java/org/opencastproject/kernel/security/TrustedHttpClientImpl.java",
          "span_kind": "primary_opencast_unconditional_digest_credential_anchor",
          "start_line": 351,
          "symbol": "TrustedHttpClientImpl.execute credential header and provider setup"
        },
        {
          "end_line": 1727,
          "file": "modules/ingest-service-impl/src/main/java/org/opencastproject/ingest/impl/IngestServiceImpl.java",
          "span_kind": "mediapackage_url_to_trusted_client_anchor",
          "start_line": 1700,
          "symbol": "IngestServiceImpl.addContentToRepo client selection"
        },
        {
          "end_line": 185,
          "file": "modules/kernel/src/main/java/org/opencastproject/kernel/security/TrustedHttpClientImpl.java",
          "span_kind": "global_digest_user_pass_config_anchor",
          "start_line": 178,
          "symbol": "TrustedHttpClientImpl.activate digest credential configuration"
        }
      ],
      "case_id": "case::20ce2f6498f4d427350f",
      "cve_ids": [
        "CVE-2025-54380"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "opencast__opencast::CVE-2025-54380",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The ingest path takes a mediapackage element URI, creates an HttpGet, and derives cluster URL matching from the current organization servers.",
        "When the URI matches the organization cluster URL set, the vulnerable checkout uses the system TrustedHttpClient for the fetch; otherwise it creates a no-auth client.",
        "The pre-fix implementation keeps separate no-auth and custom-auth clients, while system digest behavior remains inside TrustedHttpClientImpl."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 88,
          "file": "packages/payload/src/uploads/safeFetch.ts",
          "span_kind": "phase21_025_review_entry_window",
          "start_line": 57,
          "symbol": "safeFetch"
        },
        {
          "end_line": 68,
          "file": "packages/payload/src/uploads/getExternalFile.ts",
          "span_kind": "phase21_025_review_entry_window",
          "start_line": 40,
          "symbol": "getExternalFile"
        }
      ],
      "case_id": "case::24cd2238a376759d921e",
      "cve_ids": [
        "CVE-2026-27567"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "payloadcms__payload::CVE-2026-27567",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.025 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster contains 40 CVEs primarily related to Server-Side Request Forgery (SSRF) due to missing or incomplete validation of user-supplied URLs before making outbound HTTP requests. It also includes issues with TLS certificate validation, credential exposure, authorization context confusion, regular expression denial of service, and concurrency race conditions. The common thread is inadequate security checks in network-facing operations.",
  "guideline_group_key": "cluster_0070__mech_ssrf_redirect_following_client",
  "guideline_id": "gl_mech_0116",
  "guideline_text": "Trace attacker-controlled URLs or server-controlled redirect responses into HTTP clients that automatically follow redirects or reuse a previously validated URL decision. Report code paths where the final redirected scheme, host, port, and resolved address are not revalidated before the sensitive network request. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 28 historical CVE example(s), not as a project-specific signature. A safe implementation should disable automatic redirects or revalidate every redirect hop against the same allowlist and address policy.",
  "judge_selection_reason": "clean_control",
  "mechanism": {
    "family": "ssrf",
    "mechanism_id": "mech_ssrf_redirect_following_client",
    "name": "SSRF through redirect-following client"
  },
  "structural_sanity": {
    "assigned_case_count": 15,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [],
    "metadata_cve_count": 15,
    "primary_hcvr_majority": "ssrf",
    "primary_hcvr_purity": 0.9333,
    "source_cve_count": 28
  }
}