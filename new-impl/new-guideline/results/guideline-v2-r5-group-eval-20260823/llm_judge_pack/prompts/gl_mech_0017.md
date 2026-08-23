You are judging a reusable security-audit guideline group.

Evaluate whether the guideline accurately describes a coherent vulnerability mechanism shared by the listed cases.
Do not evaluate embedding recall, rank, or whether known anchors were hit.
Do not require all cases to share the same CWE or dataset label; those labels are only weak context.
Prefer mechanism-level judgments: source shape, sink shape, missing guard, exploit precondition, and safe fix.

Return JSON only with this schema:
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

Guideline group payload:
{
  "case_examples": [
    {
      "anchor_examples": [
        {
          "end_line": 124,
          "file": "modules/jpawebapi/src/com/haulmont/addon/jpawebapi/api/controller/RestFileDownloadController.java",
          "span_kind": "primary_download_endpoint_anchor",
          "start_line": 81,
          "symbol": "RestFileDownloadController.download"
        },
        {
          "end_line": 117,
          "file": "modules/jpawebapi/src/com/haulmont/addon/jpawebapi/api/controller/RestFileDownloadController.java",
          "span_kind": "primary_inline_disposition_anchor",
          "start_line": 112,
          "symbol": "RestFileDownloadController.download response headers"
        },
        {
          "end_line": 217,
          "file": "modules/jpawebapi/src/com/haulmont/addon/jpawebapi/api/controller/RestFileDownloadController.java",
          "span_kind": "html_content_type_anchor",
          "start_line": 211,
          "symbol": "RestFileDownloadController.getContentType"
        },
        {
          "end_line": 180,
          "file": "modules/jpawebapi/src/com/haulmont/addon/jpawebapi/api/controller/RestFileDownloadController.java",
          "span_kind": "file_bytes_response_anchor",
          "start_line": 127,
          "symbol": "RestFileDownloadController.writeResponse"
        },
        {
          "end_line": 63,
          "file": "modules/jpawebapi/src/com/haulmont/addon/jpawebapi/api/config/JpaWebApiConfig.java",
          "span_kind": "missing_inline_allowlist_config_anchor",
          "start_line": 30,
          "symbol": "JpaWebApiConfig"
        }
      ],
      "case_id": "case::478dc708d29a639d2d68",
      "cve_ids": [
        "CVE-2025-32961"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "cuba-platform__jpawebapi::CVE-2025-32961",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The GET /download endpoint validates the session, loads FileDescriptor from request parameter f, derives the filename, sets Content-Type from getContentType, and sets Content-Disposition from request parameter a before writing the response.",
        "The vulnerable response path uses fd.getName for the filename, getContentType(fd) for the MIME type, and Boolean.valueOf(request.getParameter(\"a\")) to decide attachment versus inline without checking the file extension.",
        "After the headers are set, writeResponse retrieves the stored file content from the backend file service and copies it to the servlet output stream, making the selected Content-Type and inline disposition browser-visible."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 103,
          "file": "modules/rest-api/src/com/haulmont/addon/restapi/api/controllers/FileDownloadController.java",
          "span_kind": "primary_files_endpoint_anchor",
          "start_line": 68,
          "symbol": "FileDownloadController.downloadFile"
        },
        {
          "end_line": 98,
          "file": "modules/rest-api/src/com/haulmont/addon/restapi/api/controllers/FileDownloadController.java",
          "span_kind": "primary_inline_disposition_anchor",
          "start_line": 90,
          "symbol": "FileDownloadController.downloadFile response headers"
        },
        {
          "end_line": 124,
          "file": "modules/rest-api/src/com/haulmont/addon/restapi/api/controllers/FileDownloadController.java",
          "span_kind": "html_content_type_anchor",
          "start_line": 118,
          "symbol": "FileDownloadController.getContentType"
        },
        {
          "end_line": 116,
          "file": "modules/rest-api/src/com/haulmont/addon/restapi/api/controllers/FileDownloadController.java",
          "span_kind": "file_bytes_response_anchor",
          "start_line": 105,
          "symbol": "FileDownloadController.downloadFromMiddlewareAndWriteResponse"
        },
        {
          "end_line": 126,
          "file": "modules/global/src/com/haulmont/addon/restapi/api/config/RestApiConfig.java",
          "span_kind": "missing_inline_allowlist_config_anchor",
          "start_line": 37,
          "symbol": "RestApiConfig"
        }
      ],
      "case_id": "case::dce11f1f02a2c8460e41",
      "cve_ids": [
        "CVE-2025-32960"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "cuba-platform__restapi::CVE-2025-32960",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The REST file download handler parses fileDescriptorId, loads the FileDescriptor, sets Content-Type from getContentType, and sets Content-Disposition from the optional attachment request parameter before streaming the file.",
        "The vulnerable response path uses the loaded FileDescriptor for MIME type and filename, and maps BooleanUtils.isTrue(attachment) directly to attachment versus inline without checking file extension.",
        "After vulnerable headers are set, the controller opens the stored file stream via FileLoader and copies it to the servlet output stream."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "A set of vulnerabilities caused by missing or insufficient validation of user-supplied data used in file path construction, file upload/download, and resource access. Common weaknesses include lack of path canonicalization, absence of file extension/MIME type allow-lists, missing inline disposition allow-lists, and failure to enforce size limits, leading to path traversal, arbitrary file upload, XSS, SSRF, and disk exhaustion.",
  "guideline_group_key": "cluster_0004__pending_mech_cluster_4_missing_allow_list_for_inline_content_disposition_leading_to_xss",
  "guideline_id": "gl_mech_0017",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 3 historical CVE example(s), not as a project-specific signature. A safe implementation should Introduce a configurable allow-list of safe extensions for inline serving; default to attachment for all others..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_4_missing_allow_list_for_inline_content_disposition_leading_to_xss",
    "name": "Missing allow-list for inline Content-Disposition leading to XSS"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 3
  }
}