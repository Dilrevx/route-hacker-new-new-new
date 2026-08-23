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
    "boundary_text": "Temporary directory create-delete-mkdir TOCTOU: create a temporary file, delete it, then recreate the same pathname as a directory before writing, copying, loading, or otherwise relying on that path.",
    "evidence_refs": [
      {
        "identity_key": "centic9__jgit-cookbook::CVE-2022-4817",
        "source_evidence": "structured_cves_combined: root cause identifies File.createTempFile, delete, then mkdirs on the same name; dataset trace anchors src/main/java/org/dstadler/jgit/porcelain/CleanUntrackedFiles.java:45-47 and cites patch_hunk_before output/cve_clustering/v2/patch_cache/b8cb29b43dc704708d598c60ac1881db7cf8e9c3.diff lines 27-34; fixed source uses Files.createTempDirectory."
      },
      {
        "identity_key": "devent__globalpom-utils::CVE-2018-25068",
        "source_evidence": "structured_cves_combined: createTmpDir flows through File.createTempFile, tmp.delete(), tmp.mkdir(); dataset trace anchors globalpomutils-fileresources/src/main/java/com/anrisoftware/globalpom/fileresourcemanager/FileResourceManagerProvider.java:96-104 and cites patch_hunk_before output/cve_clustering/v2/patch_cache/77a820bac2f68e662ce261ecb050c643bd7ee560.diff lines 156-158; fixed source uses Files.createTempDirectory."
      },
      {
        "identity_key": "openkm__document-management-system::CVE-2022-3969",
        "source_evidence": "structured_cves_combined: creates a temporary file, deletes it, then creates a directory with the same name; dataset trace anchors src/main/java/com/openkm/util/FileUtils.java:66-78 and cites both patch_hunk_before output/cve_clustering/v2/patch_cache/c069e4d73ab8864345c25119d8459495f45453e1.diff lines 66-78 and old source output/intermediates/multitrack_local_git_inventory_v2/repos/openkm__document-management-system__e1ee4c0becec/src/main/java/com/openkm/util/FileUtils.java lines 66-78; fixed source uses Files.createTempDirectory."
      }
    ],
    "exploit_precondition": "An attacker can write to, monitor, or race within the parent temporary/work directory and can create a file, directory, or symlink at the released pathname between deletion and directory creation.",
    "guideline_id": "gl_mech_0001",
    "mechanism_id": "mech_temp_file_delete_mkdir_race",
    "mechanism_name": "temporary directory create-delete-mkdir TOCTOU race",
    "missing_guard": "The old-side pattern has no atomic directory creation, stable directory handle, or synchronization binding the checked temporary name to the later directory use. The delete-to-mkdir interval releases the pathname, and checking mkdir or mkdirs after the fact does not prevent replacement within the race window.",
    "rationale": "Three source/patch-backed cases share the same mechanism: reserve a temporary path as a file, delete it, then recreate the same path as a directory without atomic binding. The safe fix is also consistent across the examples: replace the manual sequence with Files.createTempDirectory.",
    "recall_follow_up": "If this boundary changes the recall-consumed sidecar text, rerun same-identity P3C64 recall on the frozen 143 identity file at Top-100, Top-150, and Top-200. Also inspect whether file_permission_temp_resource cases moved out of this mechanism instead of treating them as missed positives.",
    "representative_cases": [
      "centic9__jgit-cookbook::CVE-2022-4817",
      "devent__globalpom-utils::CVE-2018-25068",
      "openkm__document-management-system::CVE-2022-3969"
    ],
    "reviewer_notes": "This row promotes only the createTempFile-delete-mkdir race boundary. Temporary-resource permission exposure remains a separate candidate boundary and should not be merged into this guideline unless source evidence shows the same release-and-recreate race.",
    "safe_fix_semantics": "Use an atomic temporary-directory creation API such as Files.createTempDirectory, keep and use the returned Path, and fail closed if creation cannot be performed with the intended ownership and permissions. Do not implement directory creation as createTempFile-delete-mkdir or createTempFile-delete-mkdirs.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The recreated directory path is then trusted as an application-controlled temporary workspace for file operations such as checkout cleanup, resource management, upload/session processing, or other subsequent reads/writes. If another actor replaces or pre-creates the path during the gap, the sensitive effect is applied to an attacker-controlled file, directory, or symlink target.",
    "source_shape": "Java code reserves a temporary pathname with File.createTempFile or equivalent, deletes the returned file object, and then calls mkdir or mkdirs on the same pathname to obtain a directory."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.