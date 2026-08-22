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
          "end_line": 108,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "phase21_057_review_entry_window",
          "start_line": 97,
          "symbol": "GuiStorageElement.setAction storage click handler"
        },
        {
          "end_line": 107,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "file_region",
          "start_line": 97,
          "symbol": "GuiStorageElement.setAction storage click handler.center_window_11"
        },
        {
          "end_line": 109,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "file_region",
          "start_line": 95,
          "symbol": "GuiStorageElement.setAction storage click handler.center_window_15"
        },
        {
          "end_line": 110,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "file_region",
          "start_line": 96,
          "symbol": "GuiStorageElement.setAction storage click handler.end_window"
        },
        {
          "end_line": 106,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "file_region",
          "start_line": 92,
          "symbol": "GuiStorageElement.setAction storage click handler.expanded_trace_window"
        }
      ],
      "case_id": "case::0375832f25fe40b72b49",
      "cve_ids": [
        "CVE-2025-62782"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "phoenix616__inventorygui::CVE-2025-62782",
      "primary_hcvr_type": "business_state_precondition",
      "trace_evidence": [
        "This label is one compact source-contract review entry for the InventoryGui bundle interaction business-state issue. The ClickType import and broader click-action switch are supporting evidence only; broad function or sliding windows are not promoted."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers vulnerabilities in inventory and slot manipulation logic where the code fails to validate slot properties (e.g., fake output slots), enforce access control (e.g., player permission to modify slots), or account for special item behaviors (e.g., Bundle items causing duplicate packets or state desynchronization). The missing checks lead to item duplication, unauthorized extraction, or state divergence, and the fixes involve adding explicit validation of slot types, permission checks, and consistency guards.",
  "guideline_group_key": "cluster_0001__mech_toctou_mutable_object_reuse",
  "guideline_id": "gl_mech_0005",
  "guideline_text": "Trace mutable files, paths, objects, identities, request fields, or shared state that are checked before use into sensitive file, state, permission, memory, or resource effects that depend on the earlier check. Report code paths where the checked value is not stabilized with a handle, lock, transaction, immutable copy, or atomic operation before the effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should bind the check to a stable reference or perform the check and effect under the same atomic operation or synchronization boundary.",
  "mechanism": {
    "family": "race_or_lifecycle",
    "mechanism_id": "mech_toctou_mutable_object_reuse",
    "name": "time-of-check to time-of-use on mutable object"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "small_group"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "business_state_precondition",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 1
  }
}