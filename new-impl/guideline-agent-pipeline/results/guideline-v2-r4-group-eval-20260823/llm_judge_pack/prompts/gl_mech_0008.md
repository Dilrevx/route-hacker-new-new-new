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
          "end_line": 84,
          "file": "src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 79,
          "symbol": ""
        }
      ],
      "case_id": "case::17d33f3743536967af66",
      "cve_ids": [
        "CVE-2025-59340"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hubspot__jinjava::CVE-2025-59340",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers vulnerabilities where attacker-controlled strings are evaluated as expression language or code by template engines, validation frameworks, or dynamic code generators without proper restrictions or sanitization. The common mistake is assuming user input is safe to interpret, leading to injection of arbitrary expressions or code that can execute arbitrary operations.",
  "guideline_group_key": "cluster_0003__mech_bean_property_reflection_escape",
  "guideline_id": "gl_mech_0008",
  "guideline_text": "Trace attacker-controlled property names, bean paths, binding keys, or conversion metadata into bean introspection, property-copy, nested binding, conversion, or reflective access APIs. Report code paths where dangerous meta-properties, nested class-loader paths, or reflective properties are not suppressed before binding. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should denylist dangerous meta-properties, restrict nested binding, and avoid exposing reflective class-loader reachable fields.",
  "mechanism": {
    "family": "reflection_or_binding",
    "mechanism_id": "mech_bean_property_reflection_escape",
    "name": "bean property reflection escape"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "small_group"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "template_expression_injection",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 1
  }
}