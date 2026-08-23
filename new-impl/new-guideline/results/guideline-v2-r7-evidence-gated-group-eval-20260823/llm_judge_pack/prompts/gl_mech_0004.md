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
          "end_line": 56,
          "file": "api/src/main/java/me/shedaniel/rei/api/common/transfer/info/stack/VanillaSlotAccessor.java",
          "span_kind": "phase21_086_review_entry_window",
          "start_line": 32,
          "symbol": "VanillaSlotAccessor.setItemStack/takeStack"
        },
        {
          "end_line": 54,
          "file": "api/src/main/java/me/shedaniel/rei/api/common/transfer/info/clean/InputCleanHandler.java",
          "span_kind": "phase21_086_review_entry_window",
          "start_line": 44,
          "symbol": "InputCleanHandler.returnSlotsToPlayerInventory"
        },
        {
          "end_line": 56,
          "file": "api/src/main/java/me/shedaniel/rei/api/common/transfer/info/stack/SlotAccessor.java",
          "span_kind": "phase21_086_review_entry_window",
          "start_line": 37,
          "symbol": "SlotAccessor"
        },
        {
          "end_line": 158,
          "file": "runtime/src/main/java/me/shedaniel/rei/impl/common/transfer/InputSlotCrafter.java",
          "span_kind": "phase21_086_review_entry_window",
          "start_line": 108,
          "symbol": "InputSlotCrafter.fillInputSlot/takeInventoryStack"
        },
        {
          "end_line": 45,
          "file": "api/src/main/java/me/shedaniel/rei/api/common/transfer/info/stack/VanillaSlotAccessor.java",
          "span_kind": "file_region",
          "start_line": 43,
          "symbol": "VanillaSlotAccessor.setItemStack/takeStack.center_window_3"
        }
      ],
      "case_id": "case::3264a48279443da15f0b",
      "cve_ids": [
        "CVE-2024-42698"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "shedaniel__roughlyenoughitems::CVE-2024-42698",
      "primary_hcvr_type": "business_state_precondition",
      "trace_evidence": [
        "This compact label covers the slot-modification precondition contract: a transfer helper must check whether the same logical slot allows modification or placement before taking from it, placing into it, or moving items through it."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers vulnerabilities in inventory and slot manipulation logic where the code fails to validate slot properties (e.g., fake output slots), enforce access control (e.g., player permission to modify slots), or account for special item behaviors (e.g., Bundle items causing duplicate packets or state desynchronization). The missing checks lead to item duplication, unauthorized extraction, or state divergence, and the fixes involve adding explicit validation of slot types, permission checks, and consistency guards.",
  "guideline_group_key": "cluster_0001__pending_mech_cluster_1_missing_access_control_for_slot_modifications",
  "guideline_id": "gl_mech_0004",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should Add allowModification and canPlace checks before any slot modification; if the check fails, throw an exception or skip the operation..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_1_missing_access_control_for_slot_modifications",
    "name": "Missing access control for slot modifications"
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
    "primary_hcvr_majority": "business_state_precondition",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 1
  }
}