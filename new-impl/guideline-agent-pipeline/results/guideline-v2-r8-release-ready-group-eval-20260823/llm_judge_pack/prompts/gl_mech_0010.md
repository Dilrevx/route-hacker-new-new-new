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
          "end_line": 353,
          "file": "src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java",
          "span_kind": "primary_symlink_overwrite_fix_anchor",
          "start_line": 328,
          "symbol": "AbstractUnArchiver.extractFile target resolution"
        },
        {
          "end_line": 383,
          "file": "src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java",
          "span_kind": "symlink_then_file_write_anchor",
          "start_line": 355,
          "symbol": "AbstractUnArchiver.extractFile write paths"
        },
        {
          "end_line": 210,
          "file": "src/main/java/org/codehaus/plexus/archiver/zip/AbstractZipUnArchiver.java",
          "span_kind": "zip_physical_order_entry_anchor",
          "start_line": 181,
          "symbol": "AbstractZipUnArchiver.execute"
        },
        {
          "end_line": 120,
          "file": "src/main/java/org/codehaus/plexus/archiver/tar/TarUnArchiver.java",
          "span_kind": "tar_symlink_entry_anchor",
          "start_line": 102,
          "symbol": "TarUnArchiver.execute"
        }
      ],
      "case_id": "case::0db3b7c33c6267bbc4da",
      "cve_ids": [
        "CVE-2023-37460"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "codehaus-plexus__plexus-archiver::CVE-2023-37460",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "ZIP extraction iterates ZipArchiveEntry objects in physical order, opens each entry stream, and passes entry name, mode, symlink destination from resolveSymlink(), and content stream into AbstractUnArchiver.extractFile().",
        "TAR extraction similarly reads TarArchiveEntry names and symlink targets, then delegates each selected entry to AbstractUnArchiver.extractFile().",
        "extractFile maps the attacker-controlled archive entry name to targetFileName and checks canonical path containment, but this block does not reject standard-file extraction to a path that is already a symbolic link."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster consists of vulnerabilities in archive extraction (ZIP, TAR, RAR) that allow directory traversal, arbitrary file write, or infinite loops. The most common root cause is the assumption that entry names are safe relative paths without canonicalization, enabling '..' sequences to escape the extraction directory. Other variants include insufficient string-based prefix checks, missing backslash normalization, symlink bypass, and missing cycle/null checks causing infinite loops.",
  "guideline_group_key": "cluster_0004__mech_archive_symlink_extraction_escape",
  "guideline_id": "gl_mech_0010",
  "guideline_text": "Trace attacker-controlled archive entries, symlink entries, link targets, or extraction order into archive extraction code that creates links, opens output files, or writes entry contents into the extraction tree. Report code paths where later writes can follow an existing or archive-created symbolic link outside the extraction root despite lexical or canonical path containment checks. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should reject unsafe symlink targets, use no-follow or race-safe filesystem operations for writes, and validate the final opened target remains inside the extraction root.",
  "judge_selection_reason": "small_group",
  "mechanism": {
    "family": "filesystem",
    "mechanism_id": "mech_archive_symlink_extraction_escape",
    "name": "archive extraction escape through symlink-following writes"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "small_group"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 1
  }
}