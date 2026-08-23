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
    "boundary_label": "candidate_boundary_03_recursive_copy_move_ancestor_guard",
    "boundary_text": "Recursive copy/move ancestor guard bypass: a file-management API accepts a destination folder and one or more source file or folder paths, verifies readability, writability, or existence, and then copies or moves an entire source folder into a destination without proving the destination is not the source itself or a child of that source. Report code paths where recursive copy or move can duplicate a parent tree into one of its own descendants, causing unauthorized file disclosure, filesystem expansion, or cross-user file exposure.",
    "evidence_refs": [
      {
        "identity_key": "obiba__opal::CVE-2025-27101",
        "source_evidence": "Public CVE metadata in assets/vulndb says Opal before 5.1.1 copied parent directories into /temp/ so all files in that parent directory were copied, including files the user should not access, impacting all users including low-privilege DataShield users."
      },
      {
        "identity_key": "obiba__opal::CVE-2025-27101",
        "source_evidence": "Pre-patch checkout 9e42d565a14f4c6ccf9935df5a42971af395decd FilesResource.updateFile lines 153-171 resolves destinationPath and dispatches action=copy or action=move over query parameter file sources. copyFrom lines 271-293 checks destination and source readability, then for folder sources calls destinationFile.copyFrom(sourceFile, Selectors.SELECT_ALL). moveToFolder lines 204-215 checks source files then calls sourceFile.moveTo(destinationFile)."
      },
      {
        "identity_key": "obiba__opal::CVE-2025-27101",
        "source_evidence": "Fix commit fca7dc9c8348064741b2e8b2c31b66660a935743 adds checkSourceIsNotParent(sourceFile, destinationFolder) before both sourceFile.moveTo and copyFrom. The new helper rejects destination.compareTo(source)==0 and walks destination.getParent() until null to reject any parent equal to source."
      }
    ],
    "exploit_precondition": "An authenticated Opal user can invoke the file copy or move API with a source folder path and a destination folder under that source, such as a folder in /temp/ that later becomes retrievable by the same user. The source folder must be readable enough for the copy path and contain files whose exposure has security impact.",
    "guideline_id": "review_mech_0017",
    "mechanism_id": "mech_recursive_copy_move_missing_ancestor_guard",
    "mechanism_name": "recursive copy or move allows source folder to be placed under itself without ancestor guard",
    "missing_guard": "The vulnerable old-side checks existence, readability, writability, destination type, and allowed file extension, but it does not check whether destinationFolder is the same as sourceFile or one of sourceFile's descendants before recursive copy or move. A same-path string check is insufficient because the vulnerable condition must compare resolved FileObject ancestry.",
    "rationale": "The advisory and patch jointly show the missing invariant: recursive folder operations must reject copying or moving a source folder into itself or its child. This is a precise mechanism distinct from generic pathname traversal.",
    "recall_follow_up": "After this boundary becomes recall-consumed text, run same-identity recall for obiba__opal::CVE-2025-27101. Inspect whether candidate windows include FilesResource.updateFile, copyFrom, moveToFolder, Selectors.SELECT_ALL, and the added checkSourceIsNotParent helper.",
    "representative_cases": [
      "obiba__opal::CVE-2025-27101"
    ],
    "reviewer_notes": "This is a resource-management ancestry invariant, not ordinary '../' path traversal. It belongs near file/resource access validation, but the guideline text should mention recursive copy/move and ancestor checks so auditors do not look only for string canonicalization.",
    "safe_fix_semantics": "Before recursive copy or move, compare resolved FileObject identities and walk destination.getParent() upward to reject destination == source and any destination parent equal to source. Apply this guard to both moveToFolder and copyFrom before sourceFile.moveTo or destinationFile.copyFrom.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "For folder sources, copyFrom selects Selectors.SELECT_ALL and copies the entire source folder tree to destinationPath + '/' + sourceFile.getName().getBaseName(); moveToFolder similarly moves source folders into the destination. The public description says copying any parent directory into a folder in /temp/ copies all files in that parent directory, including files the user should not access, allowing low-privilege users to retrieve other users' files.",
    "source_shape": "The Opal file API accepts a PUT request at /files/{path} with an action query parameter and a list of source file paths. FilesResource.updateFile resolves destinationPath to a FileObject and dispatches copy or move operations over the provided sourcesPath list."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.