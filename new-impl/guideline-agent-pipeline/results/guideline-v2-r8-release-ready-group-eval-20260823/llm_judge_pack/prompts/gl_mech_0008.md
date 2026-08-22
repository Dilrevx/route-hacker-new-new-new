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
  "case_examples": [],
  "cluster_summary": "This cluster comprises vulnerabilities where user-controlled input is used to construct file paths or resource identifiers without proper validation, canonicalization, or containment checks, enabling directory traversal, unauthorized file read/write, or resource access. A minority of outliers involve unrelated vulnerabilities like deserialization, SSRF, regular expression injection, and stored XSS.",
  "guideline_group_key": "cluster_0002__mech_temp_file_delete_mkdir_race",
  "guideline_id": "gl_mech_0008",
  "guideline_text": "Trace temporary file or directory names created in shared writable locations into manual temporary directory creation sequences such as createTempFile, delete, then mkdir or mkdirs. Report code paths where the temporary path is released between creation and directory creation, allowing another actor to replace or pre-create it before use. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should use an atomic temporary-directory API such as Files.createTempDirectory and avoid delete-then-mkdir sequences.",
  "judge_selection_reason": "source_only",
  "mechanism": {
    "family": "race_or_lifecycle",
    "mechanism_id": "mech_temp_file_delete_mkdir_race",
    "name": "temporary directory create-delete-mkdir TOCTOU race"
  },
  "structural_sanity": {
    "assigned_case_count": 0,
    "cwe_majority": "",
    "cwe_purity": 0.0,
    "flags": [
      "source_only_no_case_metadata"
    ],
    "metadata_cve_count": 0,
    "primary_hcvr_majority": "",
    "primary_hcvr_purity": 0.0,
    "source_cve_count": 1
  }
}