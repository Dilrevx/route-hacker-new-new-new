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
          "end_line": 290,
          "file": "src/requests/utils.py",
          "span_kind": "phase20_38_review_entry_source_window",
          "start_line": 284,
          "symbol": "extract_zipped_paths predictable temp extraction"
        },
        {
          "end_line": 288,
          "file": "src/requests/utils.py",
          "span_kind": "file_region",
          "start_line": 286,
          "symbol": "extract_zipped_paths predictable temp extraction.center_window_3"
        },
        {
          "end_line": 289,
          "file": "src/requests/utils.py",
          "span_kind": "file_region",
          "start_line": 285,
          "symbol": "extract_zipped_paths predictable temp extraction.center_window_5"
        },
        {
          "end_line": 292,
          "file": "src/requests/utils.py",
          "span_kind": "file_region",
          "start_line": 282,
          "symbol": "extract_zipped_paths predictable temp extraction.center_window_11"
        },
        {
          "end_line": 294,
          "file": "src/requests/utils.py",
          "span_kind": "file_region",
          "start_line": 280,
          "symbol": "extract_zipped_paths predictable temp extraction.center_window_15"
        }
      ],
      "case_id": "case::4800a3c239575124a912",
      "cve_ids": [
        "CVE-2026-25645"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "psf__requests::CVE-2026-25645",
      "primary_hcvr_type": "toctou_check_use_race",
      "trace_evidence": [
        "Manual repair confirms a TOCTOU source contract: the race-sensitive object is the same derived temporary path extracted_path, checked for existence and then used for file creation/write. This is review-entry retrieval ground truth only; it does not add labels, run retrieval, or claim dynamic exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster encompasses vulnerabilities in tar and zip archive extraction where insufficient validation of member paths, link targets, header fields, and resource limits allows path traversal, arbitrary file writes, denial of service, or race conditions. The flaws commonly arise from missing canonicalization (e.g., os.path.realpath, os.path.normpath), flawed base directory comparison logic, or incomplete input sanitization.",
  "guideline_group_key": "cluster_0006__mech_temp_file_delete_mkdir_race",
  "guideline_id": "gl_mech_0015",
  "guideline_text": "Trace temporary file or directory names created in shared writable locations into manual temporary directory creation sequences such as createTempFile, delete, then mkdir or mkdirs. Report code paths where the temporary path is released between creation and directory creation, allowing another actor to replace or pre-create it before use. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should use an atomic temporary-directory API such as Files.createTempDirectory and avoid delete-then-mkdir sequences.",
  "judge_selection_reason": "small_group",
  "mechanism": {
    "family": "race_or_lifecycle",
    "mechanism_id": "mech_temp_file_delete_mkdir_race",
    "name": "temporary directory create-delete-mkdir TOCTOU race"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "small_group"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "toctou_check_use_race",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 1
  }
}