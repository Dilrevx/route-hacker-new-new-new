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
    "boundary_label": "candidate_boundary_02_multipart_original_filename_write",
    "boundary_text": "Multipart original-filename path write: a web upload handler reads MultipartFile.getOriginalFilename or an equivalent client-supplied upload filename and concatenates it into a local temporary directory, permanent upload directory, remote SFTP destination, script dependency path, or artifact storage path before stripping client path components and rejecting empty or unsafe names. Report code paths where an authenticated or unauthenticated uploader can use path separators or traversal-bearing filenames to write outside the intended per-user directory or influence the stored file path.",
    "evidence_refs": [
      {
        "identity_key": "zhaoyachao__zdh_web::CVE-2025-65897",
        "source_evidence": "Public CVE metadata in assets/vulndb describes insufficient validation of file upload paths in zdh_web through 5.6.17, allowing an authenticated user to write arbitrary files to the server filesystem. Pre-patch checkout 066925f84fb20cce06ad38d56c2803abaa927815 ZdhEtlController.etl_task_add_file lines 215-239 reads up_file.getOriginalFilename(), builds new File(zdhNginx.getTmp_dir() + \"/\" + owner + \"/\" + fileName), writes the upload stream to that path, and passes fileName to SFTP upload."
      },
      {
        "identity_key": "zhaoyachao__zdh_web::CVE-2025-65897",
        "source_evidence": "Pre-patch ZdhSshController lines 156-166 and 247-256 read jar_file.getOriginalFilename() and continue only on null/blank checks before storing file_name in JarFileInfo and later using upload paths. Fix commit b2423378a8bf83f159f19ce4e14eac71c939793a replaces these calls with MultipartFileUtil.getFileName(jar_file)."
      },
      {
        "identity_key": "zhaoyachao__zdh_web::CVE-2025-65897",
        "source_evidence": "Fix commit b2423378a8bf83f159f19ce4e14eac71c939793a adds MultipartFileUtil.getFileName: it reads multipartFile.getOriginalFilename(), returns null when empty, then uses Paths.get(fileName).getFileName().toString() to strip client-supplied path components before controller code builds filesystem paths."
      }
    ],
    "exploit_precondition": "An authenticated user can submit a multipart upload to affected zdh_web upload endpoints and control the original filename field supplied by the client. The server process must have write permission to the targeted filesystem location for overwrite or privilege-escalation impact.",
    "guideline_id": "review_mech_0017",
    "mechanism_id": "mech_multipart_original_filename_path_write",
    "mechanism_name": "multipart original filename used in server-side file path without basename normalization",
    "missing_guard": "The vulnerable code uses MultipartFile.getOriginalFilename directly and only checks null or blankness in some paths. It does not reduce the supplied filename to its basename, reject path separators, or prove the final path remains inside the intended per-user upload directory before writing or forwarding the file.",
    "rationale": "The patch replaces direct original-filename use with basename extraction at each upload path and adds a central helper, which supports a reusable upload-filename-to-file-write mechanism.",
    "recall_follow_up": "After this boundary is promoted into recall-consumed sidecar text, run same-identity recall for zhaoyachao__zdh_web::CVE-2025-65897 and inspect whether the selected windows include getOriginalFilename, tempFile construction, Files.newOutputStream/FileCopyUtils.copy, and MultipartFileUtil.getFileName. Do not count generic path traversal hits unless they overlap the upload filename flow.",
    "representative_cases": [
      "zhaoyachao__zdh_web::CVE-2025-65897"
    ],
    "reviewer_notes": "Keep this boundary separate from static-resource path traversal and archive traversal: the source is the multipart original filename metadata and the effect is server-side upload write or file propagation, not serving a request path.",
    "safe_fix_semantics": "Centralize upload filename extraction through a helper that returns null for empty filenames and strips all client-supplied directory components before the name is concatenated into local or remote upload paths. A stronger implementation would also reject traversal-like names and enforce canonical containment at the final write path.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The derived filename reaches local file writes through new File(zdhNginx.getTmp_dir() + \"/\" + owner + \"/\" + fileName) and FileCopyUtils.copy(up_file.getInputStream(), Files.newOutputStream(tempFile.toPath())), and also reaches SFTP upload paths and task jar metadata. The public description states authenticated users can write arbitrary files to the server filesystem, potentially overwriting files and enabling privilege escalation or remote code execution.",
    "source_shape": "The vulnerable handlers receive MultipartFile parameters from controller methods and read the browser-supplied original filename with getOriginalFilename. The filename is stored in task metadata and concatenated into server-side temporary paths under zdhNginx.getTmp_dir() and owner-specific upload directories."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.