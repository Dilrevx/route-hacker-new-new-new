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
          "end_line": 82,
          "file": "jt-jiffle/jt-jiffle-language/src/main/java/it/geosolutions/jaiext/jiffle/parser/node/Script.java",
          "span_kind": "phase21_009_review_entry_window",
          "start_line": 69,
          "symbol": "Script.Script"
        }
      ],
      "case_id": "case::9d192ecc33ed14b71011",
      "cve_ids": [
        "CVE-2022-24816"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "geosolutions_it__jai_ext::CVE-2022-24816",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21.009 materialized this label only after taking a Phase 21.007 source-acquisition work order, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers vulnerabilities where attacker-controlled strings are evaluated as expression language or code by template engines, validation frameworks, or dynamic code generators without proper restrictions or sanitization. The common mistake is assuming user input is safe to interpret, leading to injection of arbitrary expressions or code that can execute arbitrary operations.",
  "guideline_group_key": "cluster_0003__pending_mech_cluster_3_unsanitized_input_in_dynamically_generated_code",
  "guideline_id": "gl_mech_0012",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should Escape or sanitize user input before embedding into generated code: for Java comments escape '*/' and '/*', for Groovy scripts escape quotes and dollar signs..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_3_unsanitized_input_in_dynamically_generated_code",
    "name": "Unsanitized Input in Dynamically Generated Code"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "small_group",
      "pending_review"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "template_expression_injection",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 2
  }
}