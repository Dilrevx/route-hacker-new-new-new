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
    "boundary_decision": "promote_boundary",
    "boundary_label": "candidate_boundary_01",
    "boundary_text": "Path traversal through missing normalized containment: attacker-controlled filenames, object keys, upload identifiers, archive entries, path fragments, or resource names are resolved beneath an intended base directory and then used for file read, write, delete, list, existence check, or metadata operations before the exact resolved path is normalized or canonicalized and verified to remain under that base. The boundary covers server-side filesystem or filesystem-backed object-store paths where traversal components, separator variants, or prefix confusion can escape the intended root.",
    "evidence_refs": [
      {
        "identity_key": "dspace__dspace::CVE-2022-31194",
        "source_evidence": "The r8 group report and unified dataset source evidence record DSpace JSPUI upload traversal in snapshot eca7968be7d6b9f8f5f302c9fc09f8186ed4809e. SubmissionController.DoGetResumable appends request-controlled resumableIdentifier to upload.temp.dir or java.io.tmpdir, creates the resulting directory, builds a part file path from resumableChunkNumber, and checks/deletes that file without canonical containment. FileUploadRequest similarly builds chunkDirPath and chunkPath from tempDir plus request parameters and writes uploaded chunks when the directory exists; the normal multipart branch writes a temp file from tempDir plus the submitted filename. The 5.x fix adds canonical path checks for the resumable directory, resumable chunk file, and normal upload temp file."
      },
      {
        "identity_key": "gaul__s3proxy::CVE-2025-24961",
        "source_evidence": "The r8 group report records AbstractNio2BlobStore path traversal anchors. list() accepts a caller-controlled prefix from ListContainerOptions, derives dirPrefix and pathPrefix under root.resolve(container), and passes pathPrefix to listHelper() without checking normalized containment. getBlob() resolves the caller-controlled key against root.resolve(container) and then reads file attributes and user-defined attributes from that path. putBlob() resolves blob.getMetadata().getName() under the container, derives a temporary path from the same unvalidated name, and can create directories or write content at the resolved path. removeBlob and access-permission operations also operate on resolved paths."
      }
    ],
    "exploit_precondition": "An attacker can control or influence the upload identifier, chunk number, object key, prefix, filename, archive entry, or comparable path fragment, and the server process has filesystem permissions such that escaping the intended base directory affects files or metadata outside the allowed container or temporary upload area.",
    "guideline_id": "gl_mech_0005",
    "mechanism_id": "mech_path_traversal_missing_normalized_containment",
    "mechanism_name": "path traversal through missing normalized base-directory containment",
    "missing_guard": "The old-side flows do not enforce normalized or canonical containment of the exact resolved destination before the file operation. DSpace builds temp directories and chunk paths from request parameters without canonical containment under upload.temp.dir or java.io.tmpdir. S3Proxy resolves object keys and prefixes under a container root and uses them for list/read/write/delete/access operations without checking that the normalized path stays inside the container directory. A guard applied to a different value or a string prefix check that can be bypassed by path semantics would not satisfy this boundary.",
    "rationale": "The source-reviewed DSpace and S3Proxy examples support a reusable normalized-containment path traversal mechanism. The row deliberately does not claim all 48 historical members are source-reviewed and does not use review-entry-only cases as promotion evidence.",
    "recall_follow_up": "If this boundary changes recall-consumed guideline text, rerun same-identity P3C64 recall first for dspace__dspace::CVE-2022-31194 and gaul__s3proxy::CVE-2025-24961, then rerun the frozen 143 identity set at Top-100, Top-150, and Top-200. Inspect whether query wording retrieves both upload temp path construction and object-store key resolution without using known anchors, labels, or regex fallback in retrieval.",
    "representative_cases": [
      "dspace__dspace::CVE-2022-31194",
      "gaul__s3proxy::CVE-2025-24961"
    ],
    "safe_fix_semantics": "A safe implementation constructs the destination with path-aware APIs, normalizes or canonicalizes the final path under the intended base, rejects absolute paths, traversal components, separator-confusion variants, and prefix-confusion escapes, then enforces base-directory containment on the same path immediately before read/write/delete/list/metadata effects. For object-store abstractions, every operation that resolves a key or prefix to local filesystem state must share the same containment helper.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The resolved paths reach sensitive filesystem effects. DSpace creates upload directories, checks/deletes chunk files, and writes upload chunks or normal multipart temp files under the temporary upload root. S3Proxy lists paths, reads blob attributes, writes blob content through a temporary path derived from the same object name, deletes blobs, and accesses permission metadata from the resolved path.",
    "source_shape": "The reviewed source-trace examples take request or API-controlled path material and append or resolve it under an application base directory: DSpace derives temporary upload directories and chunk paths from resumable upload parameters, while S3Proxy resolves caller-controlled object keys or prefixes under root.resolve(container)."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.