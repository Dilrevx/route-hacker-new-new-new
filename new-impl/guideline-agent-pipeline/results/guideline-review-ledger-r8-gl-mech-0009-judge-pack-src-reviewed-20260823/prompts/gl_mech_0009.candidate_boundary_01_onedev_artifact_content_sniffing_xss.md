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
    "boundary_label": "candidate_boundary_01_onedev_artifact_content_sniffing_xss",
    "boundary_text": "Artifact download content-sniffing XSS: user-uploaded build artifacts, attachments, generated files, or repository artifacts are served back to browsers with a Content-Type derived from file content, extension, or a MIME detector, and the response lacks a defensive `X-Content-Type-Options: nosniff` policy or forced attachment/binary type. Report artifact-serving paths where attacker-supplied HTML or script-bearing content can be rendered as active same-origin browser content instead of being delivered as inert download data.",
    "evidence_refs": [
      {
        "identity_key": "theonedev__onedev::CVE-2022-39207",
        "source_evidence": "Structured CVE input records OneDev CVE-2022-39207 as stored XSS via user-uploaded file served with content-sniffed MIME type: user-uploaded artifact file flows through `FileInputStream` into `ContentDetector.detectMediaType`, then into the HTTP Content-Type response header, allowing uploaded HTML to execute in the application origin."
      },
      {
        "identity_key": "theonedev__onedev::CVE-2022-39207",
        "source_evidence": "Patch adb6e31476621f824fc3227a695232df830d83ab is titled `Fix XSS attach for published artifacts`. In `server-core/src/main/java/io/onedev/server/web/resource/ArtifactResource.java`, old code wrapped `artifactFile` in `BufferedInputStream` and called `response.setContentType(ContentDetector.detectMediaType(is, artifactPath).toString())`; the fix removes ContentDetector use, adds `response.getHeaders().addHeader(\"X-Content-Type-Options\", \"nosniff\")`, and sets `response.setContentType(MimeTypes.OCTET_STREAM)`. "
      }
    ],
    "exploit_precondition": "An attacker can upload or publish a build artifact containing HTML/JavaScript, and a victim opens that artifact through OneDev's artifact-serving endpoint in a browser that honors the returned content type and origin context.",
    "guideline_id": "gl_mech_0009",
    "mechanism_id": "mech_artifact_download_content_sniffing_xss",
    "mechanism_name": "user-uploaded artifact served with sniffed active content type",
    "missing_guard": "The vulnerable resource response does not force an inert content type such as `application/octet-stream` and does not add `X-Content-Type-Options: nosniff` before returning user-controlled artifact bytes to the browser. This is not a template-expression evaluator sink; the browser rendering decision is controlled by response content type and sniffing policy.",
    "rationale": "The patch and structured source evidence show a browser content-type/sniffing failure for uploaded artifacts. The original template-expression guideline is semantically incompatible with the reviewed source-to-sink path.",
    "recall_follow_up": "This is a source-only representative without assigned frozen-143 case metadata in the r8 worklist. If this corrected boundary becomes recall-consumed sidecar text, rerun same-identity recall only on an identity set that contains theonedev__onedev::CVE-2022-39207 and materialized candidate slices for `ArtifactResource.newResourceResponse`, `ContentDetector.detectMediaType`, `MimeTypes.OCTET_STREAM`, and `X-Content-Type-Options`.",
    "representative_cases": [
      "theonedev__onedev::CVE-2022-39207"
    ],
    "reviewer_notes": "This row intentionally corrects the current r8 attribution for gl_mech_0009. The release-ready JSON labels CVE-2022-39207 as `mech_template_expression_untrusted_eval`, while the reviewed evidence supports artifact content-sniffing XSS. Do not count this case as support for template/expression evaluation; if template eval remains needed, it must be supported by different reviewed members such as the gl_mech_0040 boundaries.",
    "safe_fix_semantics": "Serve user-uploaded artifacts as inert binary data and prevent browser sniffing: set `Content-Type` to `MimeTypes.OCTET_STREAM` and add `X-Content-Type-Options: nosniff` on the artifact response instead of using content detection on uploaded artifact bytes.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The detected media type is assigned to the HTTP `Content-Type` response header for the artifact file. If an attacker can upload an artifact containing HTML or JavaScript, the browser can render it as active content under the OneDev origin when a victim opens the artifact link.",
    "source_shape": "OneDev's artifact download resource serves build artifact files selected from project/build artifact storage. The vulnerable `ArtifactResource.newResourceResponse` opens the artifact file and detects its media type from the file stream and artifact path before returning the response."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.