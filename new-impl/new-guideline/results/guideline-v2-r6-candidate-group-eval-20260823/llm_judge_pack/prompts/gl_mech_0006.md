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
          "end_line": 1656,
          "file": "src/main/java/de/themoep/inventorygui/InventoryGui.java",
          "span_kind": "phase21_069_review_entry_window",
          "start_line": 1648,
          "symbol": "InventoryGui.simulateCollectToCursor"
        },
        {
          "end_line": 1655,
          "file": "src/main/java/de/themoep/inventorygui/InventoryGui.java",
          "span_kind": "file_region",
          "start_line": 1649,
          "symbol": "InventoryGui.simulateCollectToCursor.center_window_7"
        },
        {
          "end_line": 1657,
          "file": "src/main/java/de/themoep/inventorygui/InventoryGui.java",
          "span_kind": "file_region",
          "start_line": 1647,
          "symbol": "InventoryGui.simulateCollectToCursor.center_window_11"
        },
        {
          "end_line": 1660,
          "file": "src/main/java/de/themoep/inventorygui/InventoryGui.java",
          "span_kind": "file_region",
          "start_line": 1646,
          "symbol": "InventoryGui.simulateCollectToCursor.start_window"
        },
        {
          "end_line": 1658,
          "file": "src/main/java/de/themoep/inventorygui/InventoryGui.java",
          "span_kind": "file_region",
          "start_line": 1644,
          "symbol": "InventoryGui.simulateCollectToCursor.end_window"
        }
      ],
      "case_id": "case::683db0318da2f9af162f",
      "cve_ids": [
        "CVE-2025-62783"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "phoenix616__inventorygui::CVE-2025-62783",
      "primary_hcvr_type": "business_state_precondition",
      "trace_evidence": [
        "This compact label covers the production collect-to-cursor storage state update where the read is player-scoped but the write lacks the same player/resource precondition."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 149,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "phase21_083_review_entry_window",
          "start_line": 118,
          "symbol": "GuiStorageElement.<init>.setAction"
        },
        {
          "end_line": 336,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "phase21_083_review_entry_window",
          "start_line": 324,
          "symbol": "GuiStorageElement.setStorageItem"
        },
        {
          "end_line": 116,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "phase21_083_review_entry_window",
          "start_line": 98,
          "symbol": "GuiStorageElement.<init>.setAction"
        },
        {
          "end_line": 249,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "phase21_083_review_entry_window",
          "start_line": 234,
          "symbol": "GuiStorageElement.<init>.setAction"
        },
        {
          "end_line": 134,
          "file": "src/main/java/de/themoep/inventorygui/GuiStorageElement.java",
          "span_kind": "file_region",
          "start_line": 132,
          "symbol": "GuiStorageElement.<init>.setAction.center_window_3"
        }
      ],
      "case_id": "case::ec8c7df3eb2b29ae646a",
      "cve_ids": [
        "CVE-2025-62784"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "phoenix616__inventorygui::CVE-2025-62784",
      "primary_hcvr_type": "business_state_precondition",
      "trace_evidence": [
        "This compact label covers the same logical resource precondition: the GUI slot view and backing storage slot should be reconciled before an item transfer or storage update is allowed to proceed."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers vulnerabilities in inventory and slot manipulation logic where the code fails to validate slot properties (e.g., fake output slots), enforce access control (e.g., player permission to modify slots), or account for special item behaviors (e.g., Bundle items causing duplicate packets or state desynchronization). The missing checks lead to item duplication, unauthorized extraction, or state divergence, and the fixes involve adding explicit validation of slot types, permission checks, and consistency guards.",
  "guideline_group_key": "cluster_0001__pending_mech_cluster_1_incomplete_handling_of_bundle_item_interactions_in_inventory",
  "guideline_id": "gl_mech_0006",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should Add checks for Bundle items (redraw GUI, consume event) and include player context in inventory update calls to ensure state is scoped per player..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_1_incomplete_handling_of_bundle_item_interactions_in_inventory",
    "name": "Incomplete handling of Bundle item interactions in inventory"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "business_state_precondition",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 2
  }
}