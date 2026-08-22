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
          "end_line": 5,
          "file": "src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 41,
          "file": "src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 36,
          "symbol": ""
        },
        {
          "end_line": 64,
          "file": "src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 59,
          "symbol": ""
        }
      ],
      "case_id": "case::be3bad8a33ac48371ee4",
      "cve_ids": [
        "CVE-2026-25526"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hubspot__jinjava::CVE-2026-25526",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers vulnerabilities where attacker-controlled strings are evaluated as expression language or code by template engines, validation frameworks, or dynamic code generators without proper restrictions or sanitization. The common mistake is assuming user input is safe to interpret, leading to injection of arbitrary expressions or code that can execute arbitrary operations.",
  "guideline_group_key": "cluster_0003__mech_object_owner_scope_missing_authz",
  "guideline_id": "gl_mech_0009",
  "guideline_text": "Trace attacker-selected resource identifiers, object IDs, tenant IDs, or administrative action targets into sensitive read, write, mutation, deletion, workflow, or administrative operations on the selected resource. Report code paths where the authorization decision is not bound to both the current principal and the exact resource or tenant being affected. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should check ownership or tenant scope before the effect and carry that checked identity into the data access or mutation.",
  "mechanism": {
    "family": "authorization",
    "mechanism_id": "mech_object_owner_scope_missing_authz",
    "name": "missing object-owner or tenant-scope authorization"
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