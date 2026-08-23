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
    "boundary_label": "candidate_revision",
    "boundary_text": "Predictable archive-member temporary file check-write race: code extracts a user-influenced archive member by deriving a predictable temporary file path from the member name, checks whether that path already exists, and later writes or returns that same path without binding the check and write to a unique exclusive file object. A local actor with write access to the temporary directory can pre-create or replace the predicted path so downstream consumers use attacker-controlled content.",
    "evidence_refs": [
      {
        "identity_key": "psf__requests::CVE-2026-25645",
        "source_evidence": "Remote patch cache output/cve_clustering/v2/patch_cache/66d21cb07bd6255b1280291c4fafb71803cdb3b7.diff shows old src/requests/utils.py lines 282-290 deriving tmp = tempfile.gettempdir(), extracted_path = os.path.join(tmp, member.split(\"/\")[-1]), checking if not os.path.exists(extracted_path), then opening atomic_open(extracted_path) and writing zip_file.read(member). The fixed side replaces this with tempfile.mkstemp(suffix=suffix), os.write(fd, zip_file.read(member)), and os.close(fd)."
      },
      {
        "identity_key": "psf__requests::CVE-2026-25645",
        "source_evidence": "new_unified anchor supplement validates vulnerable checkout 8b9bc8fc0f63be84602387913c4b689f19efd028 around src/requests/utils.py:280-294 and records the same tmp/gettempdir, basename-derived extracted_path, exists check, atomic_open write, and returned path."
      },
      {
        "identity_key": "psf__requests::CVE-2026-25645",
        "source_evidence": "structured_cves_combined describes the data flow as zip member path to split('/') basename to tempdir concatenation to atomic_open write, with trigger condition requiring extract_zipped_paths and temp-directory write access; the fix strategy is tempfile.mkstemp with a non-deterministic filename."
      }
    ],
    "exploit_precondition": "An application calls requests.utils.extract_zipped_paths on a path inside an attacker-influenced ZIP archive or member name, and a local attacker can write to the system temporary directory or otherwise pre-create the predictable basename-derived path before extraction.",
    "guideline_id": "gl_mech_0015",
    "mechanism_id": "mech_predictable_archive_member_temp_path_check_write_race",
    "mechanism_name": "predictable archive-member temporary file check-write race",
    "missing_guard": "The vulnerable flow lacks a random, unique, exclusive temporary-file allocation that binds the chosen pathname to the later write. The os.path.exists check does not protect the subsequent write or returned path against a pre-existing or raced file in the shared temporary directory.",
    "rationale": "The patch and source-window evidence support a concrete check-write race over a predictable temp file path derived from an archive member basename. The evidence does not support the prior createTempFile-delete-mkdir directory sequence, so the correct action is to promote this revised narrow boundary for semantic review while keeping recall effects separate.",
    "recall_follow_up": "If this boundary replaces the recall-consumed text for gl_mech_0015, rerun same-identity recall on the frozen 143-case identity set at Top-100, Top-150, and Top-200. Interpret any miss as a recall-side query/candidate/model issue before weakening the source-reviewed semantic boundary.",
    "representative_cases": [
      "psf__requests::CVE-2026-25645"
    ],
    "reviewer_notes": "This row revises the old r8 mechanism attribution. It should not be merged into the Java createTempFile-delete-mkdir directory race guideline and should not be treated as a generic archive traversal guideline. It is a narrow single-case mechanism unless more source-reviewed cases show the same predictable archive-member temporary path check-write race.",
    "safe_fix_semantics": "Use tempfile.mkstemp or an equivalent exclusive temporary-file creation primitive to allocate a non-deterministic path, write through the returned file descriptor or stable handle, and close it safely. A restricted TMPDIR can reduce exposure for deployments that cannot upgrade, but the code-level fix is exclusive randomized temporary-file creation instead of basename-derived check-then-write.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The same derived extracted_path is opened for writing and then returned to callers as the extracted file path. If a local actor can pre-create or replace that path, subsequent code may consume attacker-controlled file content instead of the intended archive member.",
    "source_shape": "A Python archive helper opens a ZIP file, validates that the requested member exists in the archive, derives the destination with tempfile.gettempdir() and the basename of the member path, and checks os.path.exists(extracted_path) before writing."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.