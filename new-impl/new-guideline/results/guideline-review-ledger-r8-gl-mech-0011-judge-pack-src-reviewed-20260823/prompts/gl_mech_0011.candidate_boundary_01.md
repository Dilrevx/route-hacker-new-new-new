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
    "boundary_text": "Archive-entry path escape write: an attacker-controlled archive entry name or derived entry path is resolved beneath an extraction root and then used to create directories, create links, or write file content before the same extraction path enforces normalized or canonical containment under the intended root. This includes ZIP/JAR/Simple Archive Format extraction paths where traversal components, absolute paths, separator variants, or prefix-confusion can make the resolved output target escape the extraction directory.",
    "evidence_refs": [
      {
        "identity_key": "cbeust__testng::CVE-2022-4065",
        "source_evidence": "The r8 case packet records extractSuitesFrom as the JAR-suite entry flow and testngXmlExistsInJar as the extraction helper. testngXmlExistsInJar opens the JAR, iterates JarEntry objects, obtains the entry InputStream, constructs File copyFile = new File(tempDir, jeName), and calls Files.copyFile without validating the normalized destination path."
      },
      {
        "identity_key": "codehaus-plexus__plexus-archiver::CVE-2018-1002200",
        "source_evidence": "The r8 case packet records AbstractUnArchiver.extractFile receiving archive entryName and resolving it directly with FileUtils.resolveFile(dir, entryName). The same method then creates parent directories, creates a symlink, creates a directory, or opens FileOutputStream(f) and copies archive bytes without verifying that the resolved target remains below the extraction directory."
      },
      {
        "identity_key": "dspace__dspace::CVE-2022-31195",
        "source_evidence": "The r8 case packet records processUIImport preparing per-user SAF import paths, feeding the ZIP into ItemImport.unzip(new File(dataPath), dataDir), and unzip building sourcedir/zipDir through string concatenation before prepending zipDir to ZIP entry names and writing extracted content."
      }
    ],
    "exploit_precondition": "An attacker can supply or influence an archive file whose entry names are processed by the vulnerable extraction/import path, and the server-side extraction process has write permissions such that an escaped entry can create or overwrite files outside the intended extraction directory.",
    "guideline_id": "gl_mech_0011",
    "mechanism_id": "mech_archive_entry_path_escape_write",
    "mechanism_name": "archive entry path escape write outside extraction root",
    "missing_guard": "The promoted evidence does not show a normalized or canonical path containment check applied to the resolved destination before the write/create operation. The generic missing guard is not merely lack of a string prefix check; the relevant guard must bind the exact resolved entry destination used by the write to the intended extraction root under filesystem semantics.",
    "rationale": "The source-reviewed evidence supports a reusable archive-entry traversal write mechanism and narrows the old overbroad path traversal guideline to extraction-root containment. Review-entry-only examples and cases without source trace are not used as promotion evidence.",
    "recall_follow_up": "If this boundary changes recall-consumed guideline text, rerun same-identity P3C64 recall for the representative archive-entry traversal identities first, then rerun the frozen 143 identity set at Top-100/150/200. Inspect query wording, candidate slicing, symlink handling, and budget pressure without using known anchors, CVE labels, or regex fallback in retrieval.",
    "representative_cases": [
      "cbeust__testng::CVE-2022-4065",
      "codehaus-plexus__plexus-archiver::CVE-2018-1002200",
      "dspace__dspace::CVE-2022-31195"
    ],
    "safe_fix_semantics": "A safe implementation resolves each archive entry against the extraction root, normalizes or canonicalizes using the target filesystem semantics, rejects absolute paths, traversal components, separator-confusion variants, and prefix-confusion escapes, then enforces that the final path remains under the intended root before creating directories, links, or writing content. Symlink-following writes require additional no-follow or link-target validation and may need a separate boundary.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The resolved output path is used for filesystem effects before a same-path containment guard: TestNG copies the JAR entry stream into new File(tempDir, jeName); Plexus Archiver creates parent directories, symlinks, directories, or FileOutputStream(f) for the resolved entry target; DSpace's SAF import unzip path feeds ZIP entries into an extraction loop that writes extracted files under a string-built zipDir.",
    "source_shape": "The reviewed source-trace examples share an archive extraction flow: a caller-supplied JAR/ZIP or SAF upload is opened, archive entry names are iterated, and each entry name is combined with a temporary or extraction directory to produce the output path."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.