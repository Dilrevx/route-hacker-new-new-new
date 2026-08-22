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
  "case_examples": [],
  "cluster_summary": "This cluster contains CVEs where user-controlled data is output without proper sanitization or encoding, leading to code injection. The vulnerabilities span three contexts: CSV formula injection due to missing neutralization of leading formula characters, stored cross-site scripting due to missing HTML sanitization before database storage or output, and cross-site scripting via unescaped user data in HTTP response headers.",
  "guideline_group_key": "cluster_0005__mech_html_sanitizer_policy_gap",
  "guideline_id": "gl_mech_0012",
  "guideline_text": "Trace attacker-controlled markup, HTML fragments, rich text, comments, DOM nodes, style blocks, attributes, or URI values into HTML cleaners, SafeHtml validators, DOM sanitizers, rich-text renderers, or browser-rendered sanitized output. Report code paths where the active sanitizer policy does not allowlist dangerous elements, attributes, URI schemes, DOM child nodes, comments, or malformed inputs before rendering. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should activate the restrictive sanitizer for the relevant mode, enforce element/attribute/URI allowlists after parsing, and add regression tests for the bypass form.",
  "judge_selection_reason": "source_only",
  "mechanism": {
    "family": "html_sanitization",
    "mechanism_id": "mech_html_sanitizer_policy_gap",
    "name": "HTML sanitizer policy gap or inactive allowlist"
  },
  "structural_sanity": {
    "assigned_case_count": 0,
    "cwe_majority": "",
    "cwe_purity": 0.0,
    "flags": [
      "source_only_no_case_metadata"
    ],
    "metadata_cve_count": 0,
    "primary_hcvr_majority": "",
    "primary_hcvr_purity": 0.0,
    "source_cve_count": 2
  }
}