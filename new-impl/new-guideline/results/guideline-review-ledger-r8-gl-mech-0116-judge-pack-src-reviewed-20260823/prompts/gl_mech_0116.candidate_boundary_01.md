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
    "boundary_label": "candidate_boundary_01",
    "boundary_text": "Direct URL/proxy SSRF: attacker-controlled request parameters, path components, headers, tool configuration, or equivalent request metadata are used to construct an outbound HTTP, proxy, MCP, webhook, or REST-client destination, and the server performs the request before enforcing scheme, host, port, DNS-resolved address, private-network, metadata-address, and redirect-target policy on the same destination object.",
    "evidence_refs": [
      {
        "identity_key": "bigsk1__openai-realtime-ui::CVE-2026-5803",
        "source_evidence": "Remote source snapshot /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-143-run/snapshots/bigsk1__openai-realtime-ui__188ccde27fdf/server.js lines 188-260 defines app.all('/api/proxy'), reads req.query.url into targetUrl, forwards many auth/token/key/cookie-like headers, appends remaining query parameters into fullUrl, and calls fetch(fullUrl, options) without URL parsing, host/IP/private-address policy, or redirect-hop validation. Existing artifact evidence says the fix replaces this path with parseProxyTargetUrl and fetchWithSafeRedirects."
      },
      {
        "identity_key": "cbioportal__cbioportal::CVE-2024-41668",
        "source_evidence": "Remote source snapshot /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq/hcvr-p3c64-143-run/snapshots/cbioportal__cbioportal__f6450f148916/src/main/java/org/cbioportal/proxy/ProxyController.java lines 69-83 reads request path info, strips 'proxy/', builds a URI, and passes it to exchangeData; lines 215-226 build a URI from the path and query string, create a new RestTemplate, and call restTemplate.exchange(uri, method, ...). No scheme/host/private-address or redirect-target policy is visible in this old-side span."
      },
      {
        "identity_key": "labring__fastgpt::CVE-2026-44284",
        "source_evidence": "Committed r8 evidence worklist records three source-oriented review entries: dispatchRunTool reuses or creates an MCPClient from a configured URL and calls the remote MCP tool without an internal/private-address gate; MCPClient stores a caller-provided MCP URL and constructs StreamableHTTPClientTransport or SSEClientTransport with new URL(this.url); the patch adds assertMCPUrlNotInternal backed by isInternalAddress before client creation/use. This supports the same direct untrusted endpoint-to-network-client boundary, but should still be source-expanded before final release."
      },
      {
        "identity_key": "sooperset__mcp-atlassian::CVE-2026-27826",
        "source_evidence": "Committed r5/r8 group evidence records that header-provided X-Atlassian-Jira-Url and X-Atlassian-Confluence-Url plus tokens are accepted under PAT auth and used to construct JiraConfig/JiraFetcher or ConfluenceConfig/ConfluenceFetcher without destination validation. This supports the direct endpoint/header-to-fetcher boundary and also overlaps credential-forwarding risk."
      }
    ],
    "exploit_precondition": "An attacker can influence the destination URL, path, endpoint header, tool URL, or proxy route consumed by the server-side network client, and the server runs in an environment where requests to internal or otherwise restricted destinations have security impact.",
    "guideline_id": "gl_mech_0116",
    "mechanism_id": "mech_ssrf_direct_untrusted_url_fetch",
    "mechanism_name": "direct SSRF through attacker-controlled outbound URL fetch",
    "missing_guard": "The vulnerable path does not parse and validate the exact outbound destination before the request, does not reject private or metadata address ranges after DNS resolution, does not constrain scheme/host/port through an allowlist, and does not bind any validation result to the final destination used by the network client. Redirect validation may also be missing, but redirect behavior is not required for this direct boundary.",
    "rationale": "The strongest checked examples are not redirect-specific. They show attacker-influenced destination material flowing directly into server-side network clients before destination policy. Redirect-hop validation is one possible guard, but making redirect following the mechanism overfits the old group name and loses the shared source/sink/guard shape.",
    "recall_follow_up": "If this boundary changes recall-consumed guideline text, rerun same-identity recall for the source-reviewed SSRF identities at Top-100, Top-150, and Top-200. Compare against the current redirect-following wording to see whether direct URL/proxy wording recovers bigsk1, cbioportal, FastGPT, and mcp-atlassian without using labels, known anchors, or regex fallback.",
    "representative_cases": [
      "bigsk1__openai-realtime-ui::CVE-2026-5803",
      "cbioportal__cbioportal::CVE-2024-41668",
      "labring__fastgpt::CVE-2026-44284",
      "sooperset__mcp-atlassian::CVE-2026-27826"
    ],
    "safe_fix_semantics": "Parse the requested destination into a URL object before constructing the outbound request, enforce allowed schemes and destinations, reject localhost, private, link-local, metadata, and otherwise forbidden resolved addresses, validate each redirected destination when redirects are followed, and apply the guard immediately before the same network client request that uses the destination.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The destination reaches fetch(), RestTemplate.exchange(), MCP HTTP/SSE transports, Jira/Confluence fetchers, or equivalent server-side network clients. The sensitive effect is server-side network access that can reach internal services, metadata endpoints, or privileged network paths, and may forward caller or service credentials depending on the client.",
    "source_shape": "A server endpoint, workflow/tool dispatcher, proxy controller, or integration helper accepts attacker-influenced URL material from request query parameters, path information, headers, configured MCP/Jira/Confluence endpoints, or tool metadata and carries it into an outbound request destination."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.