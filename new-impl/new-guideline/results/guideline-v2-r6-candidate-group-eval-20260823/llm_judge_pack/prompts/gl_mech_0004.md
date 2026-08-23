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
          "end_line": 36,
          "file": "src/main/java/arm32x/minecraft/commandblockide/CommandBlockIDE.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 31,
          "symbol": ""
        }
      ],
      "case_id": "case::b8d17283303c7893d77e",
      "cve_ids": [
        "CVE-2024-48645"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "arm32x__command-block-ide::CVE-2024-48645",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
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
  "guideline_group_key": "cluster_0001__mech_object_owner_scope_missing_authz",
  "guideline_id": "gl_mech_0004",
  "guideline_text": "Trace attacker-selected resource identifiers, object IDs, tenant IDs, or administrative action targets into sensitive read, write, mutation, deletion, workflow, or administrative operations on the selected resource. Report code paths where the authorization decision is not bound to both the current principal and the exact resource or tenant being affected. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should check ownership or tenant scope before the effect and carry that checked identity into the data access or mutation.",
  "mechanism": {
    "family": "authorization",
    "mechanism_id": "mech_object_owner_scope_missing_authz",
    "name": "missing object-owner or tenant-scope authorization"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authorization_bypass",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 2
  }
}