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
          "end_line": 233,
          "file": "hawtjni-runtime/src/main/java/org/fusesource/hawtjni/runtime/Library.java",
          "span_kind": "phase1_review_entry_window",
          "start_line": 204,
          "symbol": "Library.exractAndLoad"
        },
        {
          "end_line": 320,
          "file": "hawtjni-runtime/src/main/java/org/fusesource/hawtjni/runtime/Library.java",
          "span_kind": "phase1_review_entry_window",
          "start_line": 313,
          "symbol": "Library.load(File)"
        },
        {
          "end_line": 281,
          "file": "hawtjni-runtime/src/main/java/org/fusesource/hawtjni/runtime/Library.java",
          "span_kind": "phase1_review_entry_window",
          "start_line": 263,
          "symbol": "Library.extract"
        }
      ],
      "case_id": "case::aacd87928b32cf3c8e84",
      "cve_ids": [
        "CVE-2013-2035"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "fusesource__hawtjni::CVE-2013-2035",
      "primary_hcvr_type": "toctou_check_use_race",
      "trace_evidence": [
        "Manual repair confirms a TOCTOU source contract over the same-or-derived temp native library object: the old flow chooses a temp directory, creates/writes/chmods a temp file, and then uses that derived path in System.load. This checkpoint repairs source-contract metadata only; it does not add labels, run retrieval, or claim dynamic exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster consists of vulnerabilities in Java and Python libraries where temporary files or directories are created using non-atomic operations (e.g., create, delete, mkdir sequence) that introduce TOCTOU race conditions, or using APIs that default to overly permissive permissions (world-readable), allowing local attackers to read sensitive data or perform symlink attacks. Additional variants include failing to verify permission changes, manually setting overly permissive permissions, and using predictable file names that enable race attacks.",
  "guideline_group_key": "cluster_0000__mech_toctou_mutable_object_reuse",
  "guideline_id": "gl_mech_0003",
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
    "primary_hcvr_majority": "toctou_check_use_race",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 1
  }
}