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
          "end_line": 47,
          "file": "src/anthropic/lib/tools/_beta_builtin_memory_tool.py",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 42,
          "symbol": ""
        },
        {
          "end_line": 281,
          "file": "src/anthropic/lib/tools/_beta_builtin_memory_tool.py",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 275,
          "symbol": ""
        },
        {
          "end_line": 348,
          "file": "src/anthropic/lib/tools/_beta_builtin_memory_tool.py",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 342,
          "symbol": ""
        },
        {
          "end_line": 45,
          "file": "src/anthropic/lib/tools/_beta_builtin_memory_tool.py",
          "span_kind": "file_region",
          "start_line": 43,
          "symbol": "src/anthropic/lib/tools/_beta_builtin_memory_tool.py:42-47.center_window_3"
        },
        {
          "end_line": 46,
          "file": "src/anthropic/lib/tools/_beta_builtin_memory_tool.py",
          "span_kind": "file_region",
          "start_line": 42,
          "symbol": "src/anthropic/lib/tools/_beta_builtin_memory_tool.py:42-47.center_window_5"
        }
      ],
      "case_id": "case::bf013be66e3a506ec856",
      "cve_ids": [
        "CVE-2026-34450"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "anthropics__anthropic-sdk-python::CVE-2026-34450",
      "primary_hcvr_type": "file_permission_temp_resource",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 164,
          "file": "src/daemon/config.ts",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 158,
          "symbol": ""
        },
        {
          "end_line": 176,
          "file": "src/daemon/config.ts",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 171,
          "symbol": ""
        },
        {
          "end_line": 162,
          "file": "src/daemon/config.ts",
          "span_kind": "file_region",
          "start_line": 160,
          "symbol": "src/daemon/config.ts:158-164.center_window_3"
        },
        {
          "end_line": 163,
          "file": "src/daemon/config.ts",
          "span_kind": "file_region",
          "start_line": 159,
          "symbol": "src/daemon/config.ts:158-164.center_window_5"
        },
        {
          "end_line": 166,
          "file": "src/daemon/config.ts",
          "span_kind": "file_region",
          "start_line": 156,
          "symbol": "src/daemon/config.ts:158-164.center_window_11"
        }
      ],
      "case_id": "case::4d3523e4b81441af6f3a",
      "cve_ids": [
        "CVE-2026-45222"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "steipete__summarize::CVE-2026-45222",
      "primary_hcvr_type": "file_permission_temp_resource",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "File operations (read, write, delete, copy) fail to resolve symbolic links or otherwise canonicalize the final path before checking that it stays within an intended sandbox directory. This allows an attacker to escape containment via symlinks, directory traversal, or TOCTOU races where symlinks are swapped between validation and use. The cluster also includes several distinct variants: insufficient pattern-based blocking, input-sanitization flaws, permission mistakes, validation ordering errors, and a concurrency issue on shared file state.",
  "guideline_group_key": "cluster_0060__pending_mech_cluster_60_missing_restrictive_file_permissions_on_sensitive_files",
  "guideline_id": "gl_mech_0331",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should Explicitly set file mode to 0o600 and directory mode to 0o700 on creation, and apply chmod afterward to cover pre-existing files..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_60_missing_restrictive_file_permissions_on_sensitive_files",
    "name": "Missing restrictive file permissions on sensitive files"
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