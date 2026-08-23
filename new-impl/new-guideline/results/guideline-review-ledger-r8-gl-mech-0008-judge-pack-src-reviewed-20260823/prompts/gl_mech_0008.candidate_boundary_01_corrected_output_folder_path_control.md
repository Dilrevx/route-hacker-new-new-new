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
    "boundary_label": "candidate_boundary_01_corrected_output_folder_path_control",
    "boundary_text": "Attacker-controlled generator output directory: a web-exposed code generation service accepts an output directory or folder option from request-controlled generator options, concatenates it with the server temporary root, and later uses that derived path as the generator output directory, archive input, and cleanup target. If traversal components or absolute-path semantics are not removed before the filesystem effects, the request can make the service read from or delete files and directories outside the intended per-request workspace.",
    "evidence_refs": [
      {
        "identity_key": "OpenAPITools__openapi-generator::CVE-2024-35219",
        "source_evidence": "GitHub advisory GHSA-g3hr-p86p-593h states OpenAPI Generator Online before 7.6.0 allowed arbitrary file read/delete because anyone could set the output folder via the outputFolder option; the issue was fixed in version 7.6.0 by removing usage of outputFolder."
      },
      {
        "identity_key": "OpenAPITools__openapi-generator::CVE-2024-35219",
        "source_evidence": "Pull request OpenAPITools/openapi-generator#18652, merged as edbb021aadae47dcfe690313ce5119faf77f800d, is titled 'Skip setting output folder in online service' and changes modules/openapi-generator-online/src/main/java/org/openapitools/codegen/online/service/Generator.java."
      },
      {
        "identity_key": "OpenAPITools__openapi-generator::CVE-2024-35219",
        "source_evidence": "Pre-patch source at base b23dcbd1904bc8681341118904c6af8b8620fcf5 Generator.java lines 121-148 reads destPath from opts.getOptions().get(\"outputFolder\"), builds outputFolder from getTmpFolder plus destPath, and passes it to codegenConfig.setOutputDir(outputFolder). The same method later adds new File(outputFolder) to the ZIP input and deletes generated files and the output folder."
      },
      {
        "identity_key": "OpenAPITools__openapi-generator::CVE-2024-35219",
        "source_evidence": "The patch hunk replaces the request option with comments saying not to use opts.getOptions().get(\"outputFolder\") because the input can contain ../../ to access other folders in the server, and sets destPath only to language + \"-\" + type.getTypeName()."
      }
    ],
    "exploit_precondition": "An attacker can submit an OpenAPI Generator Online request with generator options containing outputFolder, and the server process has filesystem access to writable directories reachable through the chosen path. The attack is limited by server filesystem permissions and generation/cleanup behavior.",
    "guideline_id": "gl_mech_0008",
    "mechanism_id": "mech_attacker_controlled_output_directory_read_delete",
    "mechanism_name": "attacker-controlled output directory for generated artifacts",
    "missing_guard": "The vulnerable flow does not reject or ignore traversal-capable outputFolder values before binding them to generation, archive, and delete operations. There is no canonical containment check proving the final outputFolder remains under the intended per-request temporary directory, and the user-selected option is used as a trusted filesystem destination.",
    "rationale": "The authoritative advisory and patch identify outputFolder path control, arbitrary file read/delete, and removal of the request-controlled option. They do not show a createTempFile/delete/mkdir race. Promoting the corrected boundary preserves a high-quality source-reviewed mechanism and prevents an incorrect TOCTOU guideline from absorbing this CVE.",
    "recall_follow_up": "Do not evaluate OpenAPITools__openapi-generator::CVE-2024-35219 as a positive for the temporary directory create-delete-mkdir race guideline. If this corrected boundary becomes recall-consumed text for gl_mech_0008 or a new mechanism guideline, rerun same-identity recall on the frozen identity set and separately report that this was a semantic correction rather than a TOCTOU recall improvement.",
    "representative_cases": [
      "OpenAPITools__openapi-generator::CVE-2024-35219"
    ],
    "reviewer_notes": "This row intentionally corrects the r8 release-ready attribution for gl_mech_0008. The current r8 JSON labels CVE-2024-35219 as mech_temp_file_delete_mkdir_race, but the source/advisory/patch evidence supports attacker-controlled output directory path control instead. It should not be counted as evidence for createTempFile-delete-mkdir TOCTOU. If the released sidecar is updated, the old temp-directory race wording should be replaced or this member should move to a path traversal/output-directory mechanism.",
    "safe_fix_semantics": "Do not accept request-controlled outputFolder for the online service. Derive the output directory from server-controlled language and generation type under a freshly created temporary workspace, or otherwise canonicalize and enforce containment before every generation, archive, and cleanup effect. The observed patch removes opts.getOptions().get(\"outputFolder\") from destPath selection and always uses language + \"-\" + type.getTypeName().",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The derived outputFolder is built as getTmpFolder().getAbsolutePath() + File.separator + destPath, then passed to codegenConfig.setOutputDir(outputFolder), used as the directory added to the generated ZIP bundle, and later used for cleanup through file.delete() and new File(outputFolder).delete(). The advisory describes arbitrary file read and delete from attacker-selected writable directories.",
    "source_shape": "OpenAPI Generator Online accepts request-controlled generator options through GeneratorInput opts. In vulnerable Generator.generate, opts.getOptions().get(\"outputFolder\") is copied into destPath when present."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.