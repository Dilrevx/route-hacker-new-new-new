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
          "end_line": 342,
          "file": "para-core/src/main/java/com/erudika/para/core/utils/Utils.java",
          "span_kind": "hunk",
          "start_line": 330,
          "symbol": ""
        },
        {
          "end_line": 119,
          "file": "para-server/src/test/java/com/erudika/para/core/utils/UtilsTest.java",
          "span_kind": "hunk",
          "start_line": 114,
          "symbol": ""
        },
        {
          "end_line": 33,
          "file": "para-server/src/test/java/com/erudika/para/core/utils/UtilsTest.java",
          "span_kind": "hunk",
          "start_line": 17,
          "symbol": ""
        },
        {
          "end_line": 352,
          "file": "para-core/src/main/java/com/erudika/para/core/utils/Utils.java",
          "span_kind": "hunk",
          "start_line": 347,
          "symbol": ""
        }
      ],
      "case_id": "case::b0d7af465d01efe00e84",
      "cve_ids": [
        "CVE-2022-1782"
      ],
      "cwe_ids": [
        "CWE-79"
      ],
      "identity_key": "erudika__para::CVE-2022-1782",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 55,
          "file": "api/jstachio/src/main/java/io/jstach/jstachio/escapers/HtmlEscaper.java",
          "span_kind": "html_escaper_missing_single_quote_case_anchor",
          "start_line": 24,
          "symbol": "HtmlEscaper.append(CharSequence,int,int)"
        },
        {
          "end_line": 78,
          "file": "api/jstachio/src/main/java/io/jstach/jstachio/escapers/HtmlEscaper.java",
          "span_kind": "html_escaper_char_missing_single_quote_case_anchor",
          "start_line": 59,
          "symbol": "HtmlEscaper.append(char)"
        },
        {
          "end_line": 54,
          "file": "api/jstachio/src/main/java/io/jstach/jstachio/escapers/Html.java",
          "span_kind": "default_html_escaper_provider_anchor",
          "start_line": 34,
          "symbol": "Html.provider/Html.of"
        }
      ],
      "case_id": "case::f4b3b3b2eb349566388a",
      "cve_ids": [
        "CVE-2023-33962"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "jstachio__jstachio::CVE-2023-33962",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "Html is the registered text/html content type and default normal Mustache HTML escaper. Its provider() and of() methods return HtmlEscaper.Html, so escaped template variables rendered as HTML pass through HtmlEscaper.",
        "The vulnerable documentation lists the built-in escaped characters as double quote, greater-than, less-than, and ampersand; single quote is absent, matching the advisory's single-quote escaping issue.",
        "HtmlEscaper.append(CharSequence, start, end) iterates each output character and switches only on ampersand, less-than, greater-than, and double quote. Because there is no single-quote branch, a single quote in attacker-controlled escaped template data remains in the final a.append(csq, start, end) output, which is unsafe in single-quoted HTML attributes."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 349,
          "file": "test/tsd/TestGraphHandler.java",
          "span_kind": "hunk",
          "start_line": 344,
          "symbol": ""
        },
        {
          "end_line": 839,
          "file": "src/tsd/GraphHandler.java",
          "span_kind": "hunk",
          "start_line": 799,
          "symbol": ""
        },
        {
          "end_line": 133,
          "file": "test/tsd/TestGraphHandler.java",
          "span_kind": "hunk",
          "start_line": 118,
          "symbol": ""
        },
        {
          "end_line": 102,
          "file": "test/tsd/TestGraphHandler.java",
          "span_kind": "hunk",
          "start_line": 97,
          "symbol": ""
        },
        {
          "end_line": 1074,
          "file": "src/tsd/GraphHandler.java",
          "span_kind": "hunk",
          "start_line": 1071,
          "symbol": ""
        }
      ],
      "case_id": "case::a2f4c382032a05306e40",
      "cve_ids": [
        "CVE-2023-36812"
      ],
      "cwe_ids": [
        "CWE-74"
      ],
      "identity_key": "opentsdb__opentsdb::CVE-2023-36812",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster consists of 22 CVEs related to cross-site scripting (XSS) vulnerabilities in web applications that generate or process HTML/JavaScript content. The common coding mistakes include missing or incomplete output encoding for different contexts, insufficient regex-based filters for dangerous attributes, improper handling of DOM nodes during sanitization, missing allowlists for tags and URI schemes, and incorrect normalization of malformed input, allowing injection of malicious scripts.",
  "guideline_group_key": "cluster_0016__pending_mech_cluster_16_missing_context_dependent_output_encoding",
  "guideline_id": "gl_mech_0087",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 5 historical CVE example(s), not as a project-specific signature. A safe implementation should Apply the appropriate context-aware encoding function (e.g., HTML attribute encoding, JavaScript string escaping, HTML entity encoding) for all user-controlled data before interpolation..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_16_missing_context_dependent_output_encoding",
    "name": "Missing context-dependent output encoding"
  },
  "structural_sanity": {
    "assigned_case_count": 3,
    "cwe_majority": "CWE-74",
    "cwe_purity": 0.3333,
    "flags": [
      "mixed_hcvr",
      "mixed_cwe",
      "pending_review"
    ],
    "metadata_cve_count": 3,
    "primary_hcvr_majority": "unspecified",
    "primary_hcvr_purity": 0.6667,
    "source_cve_count": 5
  }
}