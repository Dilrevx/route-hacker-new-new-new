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
    "boundary_label": "candidate_boundary_02_perfree_url_upload_missing_permission_guard",
    "boundary_text": "Missing endpoint authorization for server-side URL fetch: a controller endpoint accepts an attacker-controlled URL in the request body and invokes a server-side download, import, upload, preview, or attachment-ingestion service without enforcing the same permission guard used for comparable administrative attachment or upload operations. Report paths where the request body URL reaches server-side outbound fetching or file ingestion before the endpoint-level authorization check proves the caller is allowed to trigger that network and storage effect.",
    "evidence_refs": [
      {
        "identity_key": "perfreeblog__perfreeblog::CVE-2025-60319",
        "source_evidence": "GitHub advisory GHSA-h976-6mc8-5w2v states PerfreeBlog v4.0.11 is vulnerable to SSRF due to a missing authorization check in the `uploadAttachByUrl` API endpoint in `AttachController.java`."
      },
      {
        "identity_key": "perfreeblog__perfreeblog::CVE-2025-60319",
        "source_evidence": "Pre-patch source at parent 33ed859c7ad887eeb3a33bf18ec213b5001dc9e3, `perfree-system/perfree-system-biz/src/main/java/com/perfree/controller/auth/attach/AttachController.java` lines 87-94, exposes `@PostMapping(\"/uploadAttachByUrl\")` and calls `attachService.uploadAttachByUrl(attachUploadByUrlVO.getUrl())` without `@PreAuthorize`; nearby upload/update/delete methods have permission annotations."
      },
      {
        "identity_key": "perfreeblog__perfreeblog::CVE-2025-60319",
        "source_evidence": "Pre-patch `AttachUploadByUrlVO.java` lines 11-13 defines the request-controlled `url` field with only `@NotNull`; `AttachServiceImpl.java` lines 116-140 calls `HttpUtil.downloadFileFromUrl(url, tmpSaveFile.getAbsoluteFile())`, wraps the downloaded file, uploads it, inserts an attachment, deletes the temp file, and returns the created attachment."
      },
      {
        "identity_key": "perfreeblog__perfreeblog::CVE-2025-60319",
        "source_evidence": "Fix commit 103c79165e3a41a1729188fdc8a1e90c97c0a06d modifies only `AttachController.java` by adding `@PreAuthorize(\"@ss.hasPermission('admin:attach:update')\")` immediately before `uploadAttachByUrl`, confirming that the missing endpoint permission guard is the repaired control."
      }
    ],
    "exploit_precondition": "An attacker can reach the authenticated attachment controller route without holding the administrative attachment update permission that should gate URL-based uploads, and can submit an arbitrary URL in the JSON body. The server then performs the outbound fetch from its own network position and stores the fetched content as an attachment.",
    "guideline_id": "gl_mech_0006",
    "mechanism_id": "mech_missing_endpoint_authorization_for_server_side_url_fetch",
    "mechanism_name": "missing endpoint authorization for server-side URL fetch",
    "missing_guard": "The vulnerable endpoint has no `@PreAuthorize` permission check on the same controller method that receives the URL and triggers the server-side fetch. The request body being `@Valid` only checks presence of the URL field and does not authorize the caller or restrict the outbound target. The missing guard is endpoint authorization before the SSRF-capable download operation, not a URL parser, path-parameter mismatch, or request-body resource ownership check.",
    "rationale": "The advisory and patch identify a missing authorization check on a URL-upload endpoint, while the vulnerable source shows request-body URL flow into server-side download. This is a reusable SSRF/authorization boundary, but it should not be used as evidence for body-selected resource ID mismatch authorization bypass.",
    "recall_follow_up": "This is a source-only representative not present in the 143-case `new_unified_cases.v1.jsonl` identity set. Do not count it in same-identity recall metrics unless the frozen evaluation identity set is expanded and candidate slices are materialized. If recall-consumed text changes, run same-identity recall separately and inspect whether query wording finds both the unguarded controller endpoint and the service-side `HttpUtil.downloadFileFromUrl` sink without using hidden labels, known anchors, or regex fallback.",
    "representative_cases": [
      "perfreeblog__perfreeblog::CVE-2025-60319"
    ],
    "reviewer_notes": "This row corrects the PerfreeBlog member of gl_mech_0006. It is authorization-related, but not the original path-scoped request-body resource mismatch mechanism: the body value is a URL target for a server-side fetch, and the patch adds an endpoint permission guard rather than validating body-selected resource identity against a URL path parameter.",
    "safe_fix_semantics": "Apply the same administrative attachment update permission guard to the URL-upload endpoint before reading the body URL or invoking the service-side download. The observed fix adds `@PreAuthorize(\"@ss.hasPermission('admin:attach:update')\")` immediately above `uploadAttachByUrl`; further URL allowlisting or network-range filtering would harden SSRF behavior, but the CVE's patch and advisory identify the missing authorization check as the fixed guard.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The controller passes `attachUploadByUrlVO.getUrl()` into `attachService.uploadAttachByUrl(url)`. The service derives a filename from `URLUtil.toURI(url).getPath()`, then calls `HttpUtil.downloadFileFromUrl(url, tmpSaveFile.getAbsoluteFile())`, probes the downloaded content, wraps it as a multipart file, uploads it through the configured file handler, inserts the attachment record, and returns the original URL. This is a server-side outbound URL fetch plus file-ingestion effect.",
    "source_shape": "PerfreeBlog exposes `POST /api/auth/attach/uploadAttachByUrl` with body type `AttachUploadByUrlVO`, whose `url` field is request-controlled and only has a non-null validation annotation. In the vulnerable controller, `uploadAttachByUrl` lacks `@PreAuthorize` while neighboring attachment mutations such as upload, update, and delete have explicit permission guards."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.