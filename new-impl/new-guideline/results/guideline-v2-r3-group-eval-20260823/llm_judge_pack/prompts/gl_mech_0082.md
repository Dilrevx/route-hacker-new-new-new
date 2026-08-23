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
          "end_line": 62,
          "file": "engine/src/test/java/org/hibernate/validator/test/internal/constraintvalidators/hv/SafeHtmlValidatorTest.java",
          "span_kind": "hunk",
          "start_line": 57,
          "symbol": ""
        },
        {
          "end_line": 20,
          "file": "engine/src/main/java/org/hibernate/validator/internal/constraintvalidators/hv/SafeHtmlValidator.java",
          "span_kind": "hunk",
          "start_line": 6,
          "symbol": ""
        },
        {
          "end_line": 99,
          "file": "engine/src/main/java/org/hibernate/validator/internal/constraintvalidators/hv/SafeHtmlValidator.java",
          "span_kind": "hunk",
          "start_line": 91,
          "symbol": ""
        }
      ],
      "case_id": "case::bec012d56fb5e95472d3",
      "cve_ids": [
        "CVE-2019-10219"
      ],
      "cwe_ids": [
        "CWE-79"
      ],
      "identity_key": "hibernate__hibernate-validator::CVE-2019-10219",
      "primary_hcvr_type": "iris",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 205,
          "file": "org/xwiki/xml/internal/html/DefaultHTMLCleaner.java",
          "span_kind": "primary_missing_sanitizer_filter_anchor",
          "start_line": 193,
          "symbol": "DefaultHTMLCleaner.getDefaultConfiguration prepatch"
        },
        {
          "end_line": 45,
          "file": "org/xwiki/xml/html/HTMLCleanerConfiguration.java",
          "span_kind": "restricted_mode_anchor",
          "start_line": 43,
          "symbol": "HTMLCleanerConfiguration.RESTRICTED"
        },
        {
          "end_line": 10,
          "file": "META-INF/components.txt",
          "span_kind": "component_registry_gap_anchor",
          "start_line": 1,
          "symbol": "14.5 components without sanitizer"
        },
        {
          "end_line": 82,
          "file": "org/xwiki/xml/internal/html/filter/SanitizerFilter.java",
          "span_kind": "fix_restricted_mode_activation_anchor",
          "start_line": 75,
          "symbol": "SanitizerFilter.filter after fix"
        },
        {
          "end_line": 208,
          "file": "org/xwiki/xml/internal/html/SecureHTMLElementSanitizer.java",
          "span_kind": "fix_attribute_uri_allowlist_anchor",
          "start_line": 177,
          "symbol": "SecureHTMLElementSanitizer.isAttributeAllowed/isAllowedValue after fix"
        }
      ],
      "case_id": "case::edeff30e204de76b2f14",
      "cve_ids": [
        "CVE-2023-29201"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "xwiki__xwiki-commons::CVE-2023-29201",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The prepatch API exposes restricted mode as the security-relevant cleaner parameter used by callers relying on restricted HTML cleaning.",
        "DefaultHTMLCleaner parses the input with HtmlCleaner and then applies the configured filters to the DOM.",
        "The 14.5 default filter chain includes control, body, list item, list, font, attribute, and link filters but no sanitizer allowlist filter."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 270,
          "file": "xwiki-commons-core/xwiki-commons-xml/src/main/java/org/xwiki/xml/internal/html/DefaultHTMLCleaner.java",
          "span_kind": "primary_missing_omit_comments_anchor",
          "start_line": 217,
          "symbol": "DefaultHTMLCleaner.getDefaultCleanerProperties"
        },
        {
          "end_line": 325,
          "file": "xwiki-commons-core/xwiki-commons-xml/src/main/java/org/xwiki/xml/internal/html/DefaultHTMLCleaner.java",
          "span_kind": "restricted_transform_scope_anchor",
          "start_line": 317,
          "symbol": "DefaultHTMLCleaner restricted transformations"
        },
        {
          "end_line": 182,
          "file": "xwiki-commons-core/xwiki-commons-xml/src/test/java/org/xwiki/xml/internal/html/DefaultHTMLCleanerTest.java",
          "span_kind": "comment_preservation_behavior_anchor",
          "start_line": 176,
          "symbol": "DefaultHTMLCleanerTest comment preservation"
        },
        {
          "end_line": 328,
          "file": "xwiki-commons-core/xwiki-commons-xml/src/test/java/org/xwiki/xml/internal/html/DefaultHTMLCleanerTest.java",
          "span_kind": "missing_restricted_comment_test_anchor",
          "start_line": 280,
          "symbol": "DefaultHTMLCleanerTest restricted mode coverage"
        },
        {
          "end_line": 231,
          "file": "xwiki-commons-core/xwiki-commons-xml/src/main/java/org/xwiki/xml/internal/html/SecureHTMLElementSanitizer.java",
          "span_kind": "post_parse_sanitizer_boundary_anchor",
          "start_line": 164,
          "symbol": "SecureHTMLElementSanitizer element/attribute checks"
        }
      ],
      "case_id": "case::ea46ad06ccf190b72075",
      "cve_ids": [
        "CVE-2023-29528"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "xwiki__xwiki-commons::CVE-2023-29528",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The exact checkout declares XWiki Commons 14.9-rc-1, before the advisory patched 14.10 release.",
        "This configuration flag defines restricted HTML cleaning, the mode identified by CVE-2023-29528.",
        "User-controlled HTML is parsed by HtmlCleaner, serialized to a DOM, and then passed through configured filters."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster consists of 22 CVEs related to cross-site scripting (XSS) vulnerabilities in web applications that generate or process HTML/JavaScript content. The common coding mistakes include missing or incomplete output encoding for different contexts, insufficient regex-based filters for dangerous attributes, improper handling of DOM nodes during sanitization, missing allowlists for tags and URI schemes, and incorrect normalization of malformed input, allowing injection of malicious scripts.",
  "guideline_group_key": "cluster_0016__mech_privileged_server_side_capability_exposed",
  "guideline_id": "gl_mech_0082",
  "guideline_text": "Trace lower-privilege script, template, macro, plugin, or API callers that can invoke privileged server-side capabilities into server-side include, template rendering, servlet dispatch, raw object access, internal file reads, or privileged framework APIs. Report code paths where a higher privilege check is not enforced at the API entry point before exposing the server-side capability. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 3 historical CVE example(s), not as a project-specific signature. A safe implementation should check the required higher privilege at the exposed API boundary and return no sensitive result when the caller lacks that privilege.",
  "mechanism": {
    "family": "authorization",
    "mechanism_id": "mech_privileged_server_side_capability_exposed",
    "name": "privileged server-side capability exposed to lower privilege context"
  },
  "structural_sanity": {
    "assigned_case_count": 3,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.6667,
    "flags": [
      "mixed_cwe"
    ],
    "metadata_cve_count": 3,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 3
  }
}