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
          "end_line": 27,
          "file": "ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysProfileController.java",
          "span_kind": "hunk",
          "start_line": 22,
          "symbol": ""
        },
        {
          "end_line": 174,
          "file": "ruoyi-admin/src/main/java/com/ruoyi/web/controller/system/SysProfileController.java",
          "span_kind": "hunk",
          "start_line": 168,
          "symbol": ""
        },
        {
          "end_line": 24,
          "file": "ruoyi-common/src/main/java/com/ruoyi/common/exception/file/InvalidExtensionException.java",
          "span_kind": "hunk",
          "start_line": 18,
          "symbol": ""
        }
      ],
      "case_id": "case::0e46de7f2712c5918f82",
      "cve_ids": [
        "CVE-2022-32065"
      ],
      "cwe_ids": [
        "CWE-79"
      ],
      "identity_key": "yangzongzhuan__ruoyi::CVE-2022-32065",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities where user-controlled input is used to construct file paths or resource identifiers without proper validation, canonicalization, or containment checks, enabling directory traversal, unauthorized file read/write, or resource access. A minority of outliers involve unrelated vulnerabilities like deserialization, SSRF, regular expression injection, and stored XSS.",
  "guideline_group_key": "cluster_0002__mech_html_sanitizer_policy_gap",
  "guideline_id": "gl_mech_0008",
  "guideline_text": "Trace attacker-controlled markup, HTML fragments, rich text, comments, DOM nodes, style blocks, attributes, or URI values into HTML cleaners, SafeHtml validators, DOM sanitizers, rich-text renderers, or browser-rendered sanitized output. Report code paths where the active sanitizer policy does not allowlist dangerous elements, attributes, URI schemes, DOM child nodes, comments, or malformed inputs before rendering. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should activate the restrictive sanitizer for the relevant mode, enforce element/attribute/URI allowlists after parsing, and add regression tests for the bypass form.",
  "mechanism": {
    "family": "html_sanitization",
    "mechanism_id": "mech_html_sanitizer_policy_gap",
    "name": "HTML sanitizer policy gap or inactive allowlist"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "CWE-79",
    "cwe_purity": 1.0,
    "flags": [
      "small_group"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "unspecified",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 1
  }
}