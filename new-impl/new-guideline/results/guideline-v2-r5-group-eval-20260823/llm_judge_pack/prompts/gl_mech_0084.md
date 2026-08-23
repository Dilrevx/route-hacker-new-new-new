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
          "end_line": 415,
          "file": "src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java",
          "span_kind": "primary_style_tag_child_smuggling_anchor",
          "start_line": 403,
          "symbol": "AntiSamyDOMScanner.processStyleTag first child scan"
        },
        {
          "end_line": 431,
          "file": "src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java",
          "span_kind": "missing_extra_child_removal_anchor",
          "start_line": 425,
          "symbol": "AntiSamyDOMScanner.processStyleTag first child replacement"
        },
        {
          "end_line": 359,
          "file": "src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java",
          "span_kind": "style_tag_dispatch_anchor",
          "start_line": 351,
          "symbol": "AntiSamyDOMScanner.actionValidate style tag dispatch"
        }
      ],
      "case_id": "case::45bcd51f18c27c726fad",
      "cve_ids": [
        "CVE-2022-28367"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "nahsra__antisamy::CVE-2022-28367",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "actionValidate detects a style tag and delegates the element to processStyleTag(), making processStyleTag() the security-relevant CSS sanitization path for attacker-controlled STYLE content.",
        "processStyleTag() constructs a CssScanner but then reads only ele.getFirstChild() and scans firstChild.getNodeValue(). CSS or markup carried in later child nodes of the style element is not included in the scanner input.",
        "After CSS scanning, the vulnerable code writes cleanHTML or a placeholder only to firstChild. It does not remove additional style child nodes, which is the multiple-child handling gap fixed by commit 0199e7e194dba5e7d7197703f43ebe22401e61ae."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 443,
          "file": "src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java",
          "span_kind": "primary_antisamy_style_child_forward_removal_anchor",
          "start_line": 436,
          "symbol": "AntiSamyDOMScanner.processStyleTag forward child removal"
        },
        {
          "end_line": 422,
          "file": "src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java",
          "span_kind": "style_children_combined_css_scan_anchor",
          "start_line": 409,
          "symbol": "AntiSamyDOMScanner.processStyleTag child aggregation and scan"
        },
        {
          "end_line": 359,
          "file": "src/main/java/org/owasp/validator/html/scan/AntiSamyDOMScanner.java",
          "span_kind": "style_tag_dispatch_anchor",
          "start_line": 351,
          "symbol": "AntiSamyDOMScanner.actionValidate style tag dispatch"
        }
      ],
      "case_id": "case::8c893d2dff7f43090f7f",
      "cve_ids": [
        "CVE-2022-29577"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "nahsra__antisamy::CVE-2022-29577",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "actionValidate detects style tags and delegates them to processStyleTag, making the style-tag processor the source-backed sanitization path for smuggled style content.",
        "processStyleTag aggregates textContent from each child node and scans the combined stylesheet with CssScanner, the partial fix that precedes the incomplete cleanup.",
        "The cleaned CSS is written only into the first child node, so every other child must be removed correctly for the style element to be safe."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster consists of 22 CVEs related to cross-site scripting (XSS) vulnerabilities in web applications that generate or process HTML/JavaScript content. The common coding mistakes include missing or incomplete output encoding for different contexts, insufficient regex-based filters for dangerous attributes, improper handling of DOM nodes during sanitization, missing allowlists for tags and URI schemes, and incorrect normalization of malformed input, allowing injection of malicious scripts.",
  "guideline_group_key": "cluster_0016__pending_mech_cluster_16_incomplete_dom_node_handling_in_sanitization",
  "guideline_id": "gl_mech_0084",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should Iterate over all child nodes using fragment.childNodes() or similar, handle each node type appropriately, and use descending loop for removal from live NodeList..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_16_incomplete_dom_node_handling_in_sanitization",
    "name": "Incomplete DOM node handling in sanitization"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 2
  }
}