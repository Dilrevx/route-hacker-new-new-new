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
          "end_line": 560,
          "file": "packages/kit/src/runtime/server/respond.js",
          "span_kind": "sliding_window",
          "start_line": 481,
          "symbol": "respond redirect catch"
        },
        {
          "end_line": 600,
          "file": "packages/kit/src/runtime/server/respond.js",
          "span_kind": "sliding_window",
          "start_line": 521,
          "symbol": "respond redirect catch"
        },
        {
          "end_line": 120,
          "file": "packages/kit/src/exports/index.js",
          "span_kind": "sliding_window",
          "start_line": 41,
          "symbol": "redirect"
        },
        {
          "end_line": 160,
          "file": "packages/kit/src/exports/index.js",
          "span_kind": "sliding_window",
          "start_line": 81,
          "symbol": "redirect"
        },
        {
          "end_line": 200,
          "file": "packages/kit/src/exports/index.js",
          "span_kind": "sliding_window",
          "start_line": 121,
          "symbol": "redirect"
        }
      ],
      "case_id": "case::102817129d547a0ddcf6",
      "cve_ids": [
        "CVE-2026-40074"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "sveltejs__kit::CVE-2026-40074",
      "primary_hcvr_type": "open_redirect",
      "trace_evidence": [
        "Caught Redirect objects are converted to redirect_response(e.status, e.location); the useful review entry is the location-to-header handoff rather than vulnerability proof.",
        "redirect() accepts a caller-provided location and stores location.toString() without validating that it is safe as an HTTP Location header value."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 167,
          "file": "macro-plantuml-macro/src/main/java/org/xwiki/contrib/plantuml/internal/PlantUMLMacro.java",
          "span_kind": "function",
          "start_line": 149,
          "symbol": "PlantUMLMacro.computeServer"
        },
        {
          "end_line": 160,
          "file": "macro-plantuml-macro/src/main/java/org/xwiki/contrib/plantuml/internal/PlantUMLMacro.java",
          "span_kind": "sliding_window",
          "start_line": 81,
          "symbol": "PlantUMLMacro.computeServer"
        },
        {
          "end_line": 200,
          "file": "macro-plantuml-macro/src/main/java/org/xwiki/contrib/plantuml/internal/PlantUMLMacro.java",
          "span_kind": "sliding_window",
          "start_line": 121,
          "symbol": "PlantUMLMacro.computeServer"
        },
        {
          "end_line": 221,
          "file": "macro-plantuml-macro/src/main/java/org/xwiki/contrib/plantuml/internal/PlantUMLMacro.java",
          "span_kind": "sliding_window",
          "start_line": 161,
          "symbol": "PlantUMLMacro.computeServer"
        },
        {
          "end_line": 147,
          "file": "macro-plantuml-macro/src/main/java/org/xwiki/contrib/plantuml/internal/PlantUMLMacro.java",
          "span_kind": "function",
          "start_line": 136,
          "symbol": "PlantUMLMacro.executeSync"
        }
      ],
      "case_id": "case::655995498d347a5f35d3",
      "cve_ids": [
        "CVE-2026-42140"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "xwiki-contrib__macro-plantuml::CVE-2026-42140",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "computeServer returns the macro server parameter or global PlantUML server URL without parsing or trusted-domain validation. The fix parses it as URL and checks URLSecurityManager.isDomainTrusted, confirming this as the destination-policy review entry.",
        "executeSync passes computeServer(parameters) directly into plantUMLRenderer.renderDiagram. The patch adds trusted-domain validation inside computeServer before this render-service handoff, so this span is the review entry where user/configured server selection reaches the SSRF-capable renderer."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "The cluster comprises vulnerabilities where user-controlled input is used to construct URLs (redirect targets, server-side fetch URLs, navigation destinations, or URL query strings) without adequate validation or encoding. This leads to open redirect, server-side request forgery (SSRF), cross-site scripting (XSS), token leakage, and exposure of sensitive data. The root causes include missing host allowlist checks, incomplete URL parsing allowing bypasses, and failure to encode or filter sensitive data.",
  "guideline_group_key": "cluster_0037__mech_ssrf_redirect_following_client",
  "guideline_id": "gl_mech_0175",
  "guideline_text": "Trace attacker-controlled URLs or server-controlled redirect responses into HTTP clients that automatically follow redirects or reuse a previously validated URL decision. Report code paths where the final redirected scheme, host, port, and resolved address are not revalidated before the sensitive network request. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 3 historical CVE example(s), not as a project-specific signature. A safe implementation should disable automatic redirects or revalidate every redirect hop against the same allowlist and address policy.",
  "mechanism": {
    "family": "ssrf",
    "mechanism_id": "mech_ssrf_redirect_following_client",
    "name": "SSRF through redirect-following client"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "open_redirect",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 3
  }
}