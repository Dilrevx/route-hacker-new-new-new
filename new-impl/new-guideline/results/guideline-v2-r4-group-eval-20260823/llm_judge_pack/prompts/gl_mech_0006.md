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
          "end_line": 599,
          "file": "src/main/java/org/codelibs/fess/helper/SystemHelper.java",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 594,
          "symbol": ""
        }
      ],
      "case_id": "case::e2ffaf51c7c4f09e41d0",
      "cve_ids": [
        "CVE-2025-48382"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "codelibs__fess::CVE-2025-48382",
      "primary_hcvr_type": "file_permission_temp_resource",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 43,
          "file": "src/main/java/org/apache/mahout/pig/LogisticRegression.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 38,
          "symbol": ""
        },
        {
          "end_line": 165,
          "file": "src/main/java/org/apache/mahout/pig/LogisticRegression.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 159,
          "symbol": ""
        }
      ],
      "case_id": "case::7161e4f7610c5f027b3f",
      "cve_ids": [
        "CVE-2022-4641"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "tdunning__pig-vector::CVE-2022-4641",
      "primary_hcvr_type": "file_permission_temp_resource",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "The cluster involves vulnerabilities where temporary files or directories are created with default permissions that are world-readable, or where directory creation uses a non-atomic sequence enabling TOCTOU races. The root cause is using older Java APIs (File.createTempFile, File.mkdir) or non-temporary file creation APIs without explicitly setting restrictive owner-only permissions. The fix strategies involve switching to atomic APIs like Files.createTempDirectory/Files.createTempFile with owner-only permissions, explicitly setting permissions, or checking return values of permission-setting calls.",
  "guideline_group_key": "cluster_0001__pending_mech_cluster_1_insecure_default_permissions_on_temporary_files_created_with_file_crea",
  "guideline_id": "gl_mech_0006",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should Replace File.createTempFile() with java.nio.file.Files.createTempFile(), which defaults to owner-only (0600) permissions, or immediately call setReadable/setWritable with owner-only flags after creation, optionally checking return values..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_1_insecure_default_permissions_on_temporary_files_created_with_file_crea",
    "name": "Insecure default permissions on temporary files created with File.createTempFile"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "file_permission_temp_resource",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 2
  }
}