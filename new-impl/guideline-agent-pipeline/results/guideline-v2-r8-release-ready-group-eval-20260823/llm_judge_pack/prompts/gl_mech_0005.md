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
    },
    {
      "anchor_examples": [
        {
          "end_line": 23,
          "file": "geowebcache/rest/src/main/java/org/geowebcache/rest/controller/ByteStreamController.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 15,
          "symbol": ""
        },
        {
          "end_line": 100,
          "file": "geowebcache/rest/src/main/java/org/geowebcache/rest/controller/ByteStreamController.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 79,
          "symbol": ""
        }
      ],
      "case_id": "case::34392f3c354e4da6e973",
      "cve_ids": [
        "CVE-2024-24749"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "geowebcache__geowebcache::CVE-2024-24749",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 519,
          "file": "graylog2-server/src/main/java/org/graylog2/rest/resources/system/debug/bundle/SupportBundleService.java",
          "span_kind": "primary_graylog_partial_path_traversal_anchor",
          "start_line": 515,
          "symbol": "SupportBundleService.ensureFileWithinBundleDir"
        },
        {
          "end_line": 512,
          "file": "graylog2-server/src/main/java/org/graylog2/rest/resources/system/debug/bundle/SupportBundleService.java",
          "span_kind": "support_bundle_download_sink_anchor",
          "start_line": 502,
          "symbol": "SupportBundleService.downloadBundle"
        },
        {
          "end_line": 524,
          "file": "graylog2-server/src/main/java/org/graylog2/rest/resources/system/debug/bundle/SupportBundleService.java",
          "span_kind": "support_bundle_delete_sink_anchor",
          "start_line": 521,
          "symbol": "SupportBundleService.deleteBundle"
        },
        {
          "end_line": 142,
          "file": "graylog2-server/src/main/java/org/graylog2/rest/resources/system/debug/bundle/SupportBundleResource.java",
          "span_kind": "http_filename_path_param_anchor",
          "start_line": 114,
          "symbol": "SupportBundleResource download/delete endpoints"
        }
      ],
      "case_id": "case::7bc4ecf8333ccf9469d6",
      "cve_ids": [
        "CVE-2023-41044"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "graylog2__graylog2-server::CVE-2023-41044",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The HTTP GET download endpoint receives filename as a path parameter and passes it into supportBundleService.downloadBundle through a StreamingOutput.",
        "The HTTP DELETE endpoint receives filename as a path parameter and passes it into supportBundleService.deleteBundle.",
        "downloadBundle validates the supplied filename, resolves it against bundleDir, and copies the file bytes to the output stream."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 7,
          "file": "src/at/hgz/vocabletrainer/VocableTrainerProvider.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 2,
          "symbol": ""
        },
        {
          "end_line": 23,
          "file": "src/at/hgz/vocabletrainer/VocableTrainerProvider.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 13,
          "symbol": ""
        }
      ],
      "case_id": "case::e70a71194ed3c64ca204",
      "cve_ids": [
        "CVE-2017-20181"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hgzojer__vocabletrainer::CVE-2017-20181",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities where user-controlled input is used to construct file paths or resource identifiers without proper validation, canonicalization, or containment checks, enabling directory traversal, unauthorized file read/write, or resource access. A minority of outliers involve unrelated vulnerabilities like deserialization, SSRF, regular expression injection, and stored XSS.",
  "guideline_group_key": "cluster_0002__mech_path_traversal_missing_canonical_prefix",
  "guideline_id": "gl_mech_0005",
  "guideline_text": "Trace attacker-controlled filenames, archive entries, path fragments, or resource names into file read, write, delete, extraction, or resource-loading APIs. Report code paths where the normalized absolute path is not checked to remain under the intended base directory before the file operation. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 48 historical CVE example(s), not as a project-specific signature. A safe implementation should normalize and canonicalize the resolved path, then enforce a base-directory prefix or equivalent containment check.",
  "judge_selection_reason": "label_mixed",
  "mechanism": {
    "family": "filesystem",
    "mechanism_id": "mech_path_traversal_missing_canonical_prefix",
    "name": "path traversal through missing canonical prefix check"
  },
  "structural_sanity": {
    "assigned_case_count": 18,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.9444,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 17,
    "primary_hcvr_majority": "path_archive_traversal",
    "primary_hcvr_purity": 0.6111,
    "source_cve_count": 48
  }
}