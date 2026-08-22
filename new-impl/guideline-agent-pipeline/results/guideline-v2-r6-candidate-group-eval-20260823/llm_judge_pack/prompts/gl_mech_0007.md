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
          "end_line": 163,
          "file": "Common/src/main/java/mezz/jei/common/transfer/RecipeTransferUtil.java",
          "span_kind": "phase21_061_review_entry_window",
          "start_line": 144,
          "symbol": "RecipeTransferUtil.validateSlots"
        },
        {
          "end_line": 169,
          "file": "Library/src/main/java/mezz/jei/library/transfer/BasicRecipeTransferHandler.java",
          "span_kind": "phase21_061_review_entry_window",
          "start_line": 143,
          "symbol": "BasicRecipeTransferHandler.validateTransferInfo"
        },
        {
          "end_line": 154,
          "file": "Common/src/main/java/mezz/jei/common/transfer/RecipeTransferUtil.java",
          "span_kind": "file_region",
          "start_line": 152,
          "symbol": "RecipeTransferUtil.validateSlots.center_window_3"
        },
        {
          "end_line": 155,
          "file": "Common/src/main/java/mezz/jei/common/transfer/RecipeTransferUtil.java",
          "span_kind": "file_region",
          "start_line": 151,
          "symbol": "RecipeTransferUtil.validateSlots.center_window_5"
        },
        {
          "end_line": 156,
          "file": "Common/src/main/java/mezz/jei/common/transfer/RecipeTransferUtil.java",
          "span_kind": "file_region",
          "start_line": 150,
          "symbol": "RecipeTransferUtil.validateSlots.center_window_7"
        }
      ],
      "case_id": "case::bc93c1a770923d65cf36",
      "cve_ids": [
        "CVE-2024-41565"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "mezz__justenoughitems::CVE-2024-41565",
      "primary_hcvr_type": "business_state_precondition",
      "trace_evidence": [
        "This compact label covers a JustEnoughItems recipe-transfer fake/output slot business-state precondition. Logging wording changes and the transferRecipe brace cleanup are supporting/noise hunks and are not promoted."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers vulnerabilities in inventory and slot manipulation logic where the code fails to validate slot properties (e.g., fake output slots), enforce access control (e.g., player permission to modify slots), or account for special item behaviors (e.g., Bundle items causing duplicate packets or state desynchronization). The missing checks lead to item duplication, unauthorized extraction, or state divergence, and the fixes involve adding explicit validation of slot types, permission checks, and consistency guards.",
  "guideline_group_key": "cluster_0001__pending_mech_cluster_1_missing_validation_of_fake_output_slots",
  "guideline_id": "gl_mech_0007",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should Add a check for Slot.isFake() in both validateSlots and validateTransferInfo, returning an error if any slot is fake..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_1_missing_validation_of_fake_output_slots",
    "name": "Missing validation of fake/output slots"
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