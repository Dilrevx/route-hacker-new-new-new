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

Ledger-specific instructions:
{
  "decision_values": [
    "accept",
    "revise",
    "split",
    "merge",
    "needs_evidence"
  ],
  "expected_json": {
    "actionability_score": 0.0,
    "coherence_score": 0.0,
    "coverage_score": 0.0,
    "decision": "accept|revise|split|merge|needs_evidence",
    "evidence_notes": [
      "case-level evidence or missing evidence"
    ],
    "main_issue": "short explanation",
    "retrieval_query_quality": 0.0,
    "split_suggestions": [
      "submechanism A",
      "submechanism B"
    ],
    "suggested_guideline": "rewrite if decision is revise or split"
  },
  "review_scope": [
    "Judge semantic boundary quality only.",
    "Check whether source shape, sink/effect, missing guard, exploit precondition, and safe fix are coherent.",
    "Check whether representative cases support the boundary decision.",
    "Do not judge embedding recall, known-anchor rank, Top-K metrics, or model performance.",
    "Do not invent new source evidence. If evidence is insufficient, return needs_evidence.",
    "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only."
  ],
  "task": "Review one source-reviewed guideline boundary ledger row."
}

Ledger boundary payload:
{
  "judge_mode": "source_reviewed_boundary_advisory",
  "ledger_row": {
    "boundary_decision": "mark_out_of_scope",
    "boundary_label": "candidate_boundary_04_cuba_upload_size_out_of_scope",
    "boundary_text": "Unbounded file upload size: file upload storage code streams an attacker-supplied upload into persistent or temporary storage without enforcing a configured maximum byte count before disk writes can consume server storage. This is a resource-exhaustion mechanism and should not be used as evidence for path traversal or missing path containment.",
    "evidence_refs": [
      {
        "identity_key": "cuba-platform__cuba::CVE-2025-32959",
        "source_evidence": "Public CVE metadata in assets/vulndb describes CUBA Platform before 7.2.23 as local file storage not restricting uploaded file size, enabling excessively large uploads and denial of service by running the server out of space."
      },
      {
        "identity_key": "cuba-platform__cuba::CVE-2025-32959",
        "source_evidence": "Pre-patch checkout 9ab5f77c5886712d3c29aeacaf9309f9dc543f65 FileStorage.saveStream lines 116-124 opens the target storage file and calls IOUtils.copyLarge(inputStream, os) with no max size. Fix commit 42b6c00fd0572b8e52ae31afd1babc827a3161a1 adds ServerConfig.getFileStorageMaxFileSize and changes saveStream to copy at most maxAllowedSize bytes, detect remaining unread bytes, delete the file, and throw FileStorageException."
      }
    ],
    "exploit_precondition": "An attacker can upload a very large file to an endpoint backed by local file storage, and server disk or storage quota can be exhausted.",
    "guideline_id": "review_mech_0017",
    "mechanism_id": "mech_unbounded_file_upload_size_resource_exhaustion",
    "mechanism_name": "unbounded file upload size causes storage exhaustion",
    "missing_guard": "The vulnerable code calls IOUtils.copyLarge(inputStream, os) without a maximum byte count or configured file-size guard; the issue is not path construction or containment.",
    "rationale": "The authoritative description and patch are about upload size limiting and disk exhaustion. There is no source/patch evidence of attacker-controlled pathname traversal, archive entry escape, recursive folder ancestor bypass, or final path containment failure.",
    "recall_follow_up": "Do not count cuba-platform__cuba::CVE-2025-32959 as a positive for path/resource containment recall. If a resource-exhaustion guideline is later promoted, run same-identity recall for that separate boundary and compare it independently.",
    "representative_cases": [
      "cuba-platform__cuba::CVE-2025-32959"
    ],
    "reviewer_notes": "This row documents why the CUBA member should leave the review_mech_0017 path/resource traversal bucket. It may deserve a separate resource-exhaustion upload-size guideline, but counting it as path validation evidence would lower semantic quality.",
    "safe_fix_semantics": "Add a configured maximum file-storage size, copy only up to that limit, detect unread bytes beyond the limit, delete the partially uploaded file, and return an error rather than exhausting storage.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The sensitive effect is disk/storage consumption and service error behavior when an excessively large uploaded file is copied to server storage.",
    "source_shape": "The CUBA Platform local file storage path writes an uploaded InputStream into a storage FileDescriptor path through FileStorage.saveStream."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.