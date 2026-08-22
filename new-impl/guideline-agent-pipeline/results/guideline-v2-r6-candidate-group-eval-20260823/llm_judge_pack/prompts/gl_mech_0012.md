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

Guideline group payload:
{
  "case_examples": [
    {
      "anchor_examples": [
        {
          "end_line": 9,
          "file": "src/main/java/com/zrlog/plugin/backup/controller/BackupController.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 4,
          "symbol": ""
        },
        {
          "end_line": 137,
          "file": "src/main/java/com/zrlog/plugin/backup/controller/BackupController.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 131,
          "symbol": ""
        }
      ],
      "case_id": "case::958485d29b456c0971f3",
      "cve_ids": [
        "CVE-2024-57669"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "94fzb__zrlog-plugin-backup-sql-file::CVE-2024-57669",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 43,
          "file": "apis/filesystem/src/main/java/org/jclouds/filesystem/predicates/validators/internal/FilesystemBlobKeyValidatorImpl.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 38,
          "symbol": ""
        },
        {
          "end_line": 43,
          "file": "apis/filesystem/src/main/java/org/jclouds/filesystem/predicates/validators/internal/FilesystemContainerNameValidatorImpl.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 38,
          "symbol": ""
        },
        {
          "end_line": 192,
          "file": "apis/filesystem/src/main/java/org/jclouds/filesystem/strategy/internal/FilesystemStorageStrategyImpl.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 187,
          "symbol": ""
        }
      ],
      "case_id": "case::0122d62a646b770a5a45",
      "cve_ids": [
        "CVE-2025-24961"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "apache__jclouds::CVE-2025-24961",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 27,
          "file": "modules/core/src/com/haulmont/cuba/core/app/ServerConfig.java",
          "span_kind": "hunk",
          "start_line": 27,
          "symbol": ""
        },
        {
          "end_line": 123,
          "file": "modules/core/src/com/haulmont/cuba/core/app/filestorage/FileStorage.java",
          "span_kind": "hunk",
          "start_line": 123,
          "symbol": ""
        },
        {
          "end_line": 28,
          "file": "modules/core/src/com/haulmont/cuba/core/app/ServerConfig.java",
          "span_kind": "file_region",
          "start_line": 26,
          "symbol": "modules/core/src/com/haulmont/cuba/core/app/ServerConfig.java:27-27.center_window_3"
        },
        {
          "end_line": 29,
          "file": "modules/core/src/com/haulmont/cuba/core/app/ServerConfig.java",
          "span_kind": "file_region",
          "start_line": 25,
          "symbol": "modules/core/src/com/haulmont/cuba/core/app/ServerConfig.java:27-27.center_window_5"
        },
        {
          "end_line": 30,
          "file": "modules/core/src/com/haulmont/cuba/core/app/ServerConfig.java",
          "span_kind": "file_region",
          "start_line": 24,
          "symbol": "modules/core/src/com/haulmont/cuba/core/app/ServerConfig.java:27-27.center_window_7"
        }
      ],
      "case_id": "case::923ba419c0e536e7c443",
      "cve_ids": [
        "CVE-2025-32959"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "cuba-platform__cuba::CVE-2025-32959",
      "primary_hcvr_type": "iris",
      "trace_evidence": [],
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
    },
    {
      "anchor_examples": [
        {
          "end_line": 1611,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/servlet/SubmissionController.java",
          "span_kind": "primary_resumable_get_path_traversal_anchor",
          "start_line": 1571,
          "symbol": "SubmissionController.DoGetResumable"
        },
        {
          "end_line": 110,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/util/FileUploadRequest.java",
          "span_kind": "resumable_post_chunk_write_anchor",
          "start_line": 98,
          "symbol": "FileUploadRequest resumableIdentifier branch"
        },
        {
          "end_line": 123,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/util/FileUploadRequest.java",
          "span_kind": "normal_upload_temp_write_anchor",
          "start_line": 119,
          "symbol": "FileUploadRequest normal multipart branch"
        },
        {
          "end_line": 68,
          "file": "dspace-jspui/src/main/java/org/dspace/app/webui/util/FileUploadRequest.java",
          "span_kind": "upload_temp_repository_setup_anchor",
          "start_line": 62,
          "symbol": "FileUploadRequest tempDir repository setup"
        }
      ],
      "case_id": "case::1091e0c8513d259ba9f5",
      "cve_ids": [
        "CVE-2022-31194"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dspace__dspace::CVE-2022-31194",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The JSPUI submission controller dispatches resumable.js GET probes to DoGetResumable() whenever resumableFilename is present, exposing the chunk-existence path construction to request parameters.",
        "DoGetResumable() reads upload.temp.dir or java.io.tmpdir, appends the request-controlled resumableIdentifier, creates the resulting directory, builds a part file path from resumableChunkNumber, and checks/deletes that file without canonical containment.",
        "FileUploadRequest selects upload.temp.dir or java.io.tmpdir and configures the disk upload repository there, making this base directory the root that subsequent upload writes must remain inside."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 28,
          "file": "sz-common/sz-common-core/src/main/java/com/sz/core/common/enums/CommonResponseEnum.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 22,
          "symbol": ""
        },
        {
          "end_line": 39,
          "file": "sz-common/sz-common-core/src/main/java/com/sz/core/common/enums/CommonResponseEnum.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 34,
          "symbol": ""
        },
        {
          "end_line": 5,
          "file": "sz-common/sz-common-core/src/main/java/com/sz/core/util/Utils.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 1,
          "symbol": ""
        }
      ],
      "case_id": "case::b67ce842f9b3a1b07150",
      "cve_ids": [
        "CVE-2026-3188"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "feiyuchuixue__sz-boot-parent::CVE-2026-3188",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 161,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "function",
          "start_line": 142,
          "symbol": "CommonServiceImpl.urlDownload"
        },
        {
          "end_line": 161,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "function",
          "start_line": 146,
          "symbol": "CommonServiceImpl.urlDownload"
        },
        {
          "end_line": 185,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "function",
          "start_line": 159,
          "symbol": "CommonServiceImpl.urlDownload"
        },
        {
          "end_line": 160,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "sliding_window",
          "start_line": 81,
          "symbol": "CommonServiceImpl.urlDownload"
        },
        {
          "end_line": 200,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "sliding_window",
          "start_line": 121,
          "symbol": "CommonServiceImpl.urlDownload"
        }
      ],
      "case_id": "case::84a39bdc311e873b9594",
      "cve_ids": [
        "CVE-2026-3189"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "feiyuchuixue__sz-boot-parent::CVE-2026-3189",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Manual repair confirms an SSRF source-to-sink contract in CommonServiceImpl.urlDownload: caller-controlled URL material is preserved as fileUrl and reaches Java URL.openStream on the server side. The patch adds URL parsing and an http/https-only protocol guard before openStream. This checkpoint repairs metadata only; it does not add labels, run retrieval, or claim dynamic exploit proof.",
        "tempDownload fetches a stored UploadResult URL or private OSS URL with new URL(fileUrl).openStream(). It is retained as SSRF-adjacent fetch context, but lower priority than urlDownload because the URL is loaded from stored file metadata rather than directly from this method's request parameter.",
        "These helpers parse http(s) URLs into bucket/object components used by urlDownload and private URL generation. They are useful review-entry context because parsing policy constrains what target the server eventually fetches."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 189,
          "file": "src/main/java/org/gaul/s3proxy/nio2blob/AbstractNio2BlobStore.java",
          "span_kind": "primary_fix_list_prefix_path_anchor",
          "start_line": 176,
          "symbol": "AbstractNio2BlobStore.list prefix resolution"
        },
        {
          "end_line": 353,
          "file": "src/main/java/org/gaul/s3proxy/nio2blob/AbstractNio2BlobStore.java",
          "span_kind": "primary_fix_get_blob_path_anchor",
          "start_line": 342,
          "symbol": "AbstractNio2BlobStore.getBlob path resolution"
        },
        {
          "end_line": 539,
          "file": "src/main/java/org/gaul/s3proxy/nio2blob/AbstractNio2BlobStore.java",
          "span_kind": "primary_fix_put_blob_path_anchor",
          "start_line": 526,
          "symbol": "AbstractNio2BlobStore.putBlob path resolution"
        },
        {
          "end_line": 698,
          "file": "src/main/java/org/gaul/s3proxy/nio2blob/AbstractNio2BlobStore.java",
          "span_kind": "primary_fix_delete_blob_path_anchor",
          "start_line": 692,
          "symbol": "AbstractNio2BlobStore.removeBlob path resolution"
        },
        {
          "end_line": 803,
          "file": "src/main/java/org/gaul/s3proxy/nio2blob/AbstractNio2BlobStore.java",
          "span_kind": "access_permission_path_anchor",
          "start_line": 765,
          "symbol": "AbstractNio2BlobStore.getBlobAccess and setBlobAccess"
        }
      ],
      "case_id": "case::d55b90ed06871943067c",
      "cve_ids": [
        "CVE-2025-24961"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "gaul__s3proxy::CVE-2025-24961",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "list() accepts a caller-controlled prefix from ListContainerOptions, derives dirPrefix and pathPrefix under root.resolve(container), and passes the resulting pathPrefix into listHelper() without checking that normalized traversal stays inside the container directory.",
        "getBlob() resolves the caller-controlled key against root.resolve(container) and then reads file attributes and user-defined attributes from that path, allowing traversal key components to select a path outside the container before the fix.",
        "putBlob() resolves blob.getMetadata().getName() under the container, derives a temporary path from the same unvalidated name, and can create directories or write content at the resolved path."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities where user-controlled input is used to construct file paths or resource identifiers without proper validation, canonicalization, or containment checks, enabling directory traversal, unauthorized file read/write, or resource access. A minority of outliers involve unrelated vulnerabilities like deserialization, SSRF, regular expression injection, and stored XSS.",
  "guideline_group_key": "cluster_0002__mech_path_traversal_missing_canonical_prefix",
  "guideline_id": "gl_mech_0012",
  "guideline_text": "Trace attacker-controlled filenames, archive entries, path fragments, or resource names into file read, write, delete, extraction, or resource-loading APIs. Report code paths where the normalized absolute path is not checked to remain under the intended base directory before the file operation. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 89 historical CVE example(s), not as a project-specific signature. A safe implementation should normalize and canonicalize the resolved path, then enforce a base-directory prefix or equivalent containment check.",
  "mechanism": {
    "family": "filesystem",
    "mechanism_id": "mech_path_traversal_missing_canonical_prefix",
    "name": "path traversal through missing canonical prefix check"
  },
  "structural_sanity": {
    "assigned_case_count": 27,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.9259,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 26,
    "primary_hcvr_majority": "path_archive_traversal",
    "primary_hcvr_purity": 0.5185,
    "source_cve_count": 89
  }
}