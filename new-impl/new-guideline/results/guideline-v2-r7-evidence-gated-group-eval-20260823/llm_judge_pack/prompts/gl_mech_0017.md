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
          "end_line": 26,
          "file": "opal-core-ws/src/main/java/org/obiba/opal/web/FilesResource.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 20,
          "symbol": ""
        },
        {
          "end_line": 49,
          "file": "opal-core-ws/src/main/java/org/obiba/opal/web/FilesResource.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 43,
          "symbol": ""
        },
        {
          "end_line": 216,
          "file": "opal-core-ws/src/main/java/org/obiba/opal/web/FilesResource.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 211,
          "symbol": ""
        }
      ],
      "case_id": "case::758532cf3e52cc69214e",
      "cve_ids": [
        "CVE-2025-27101"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "obiba__opal::CVE-2025-27101",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 124,
          "file": "bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/ManagerSettings.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 109,
          "symbol": ""
        },
        {
          "end_line": 89,
          "file": "bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/StateBeanMessageBodyWriter.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 27,
          "file": "bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/backend/model/ConfigBean.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 1,
          "symbol": ""
        }
      ],
      "case_id": "case::59d52bd6401ba855b021",
      "cve_ids": [
        "CVE-2024-42468"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "openhab__openhab-webui::CVE-2024-42468",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 94,
          "file": "solon-projects/solon-web/solon-web-staticfiles/src/main/java/org/noear/solon/web/staticfiles/StaticMappings.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 68,
          "symbol": ""
        }
      ],
      "case_id": "case::3300b1f8e1c02036f1e8",
      "cve_ids": [
        "CVE-2025-1584"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "opensolon__solon::CVE-2025-1584",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 237,
          "file": "src/main/java/com/zyc/zdh/controller/ZdhEtlController.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 214,
          "symbol": ""
        },
        {
          "end_line": 161,
          "file": "src/main/java/com/zyc/zdh/controller/ZdhSshController.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 155,
          "symbol": ""
        },
        {
          "end_line": 253,
          "file": "src/main/java/com/zyc/zdh/controller/ZdhSshController.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 246,
          "symbol": ""
        }
      ],
      "case_id": "case::a6049798bafe617fbfa2",
      "cve_ids": [
        "CVE-2025-65897"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "zhaoyachao__zdh_web::CVE-2025-65897",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities where user-controlled input is used to construct file paths or resource identifiers without proper validation, canonicalization, or containment checks, enabling directory traversal, unauthorized file read/write, or resource access. A minority of outliers involve unrelated vulnerabilities like deserialization, SSRF, regular expression injection, and stored XSS.",
  "guideline_group_key": "cluster_0002__pending_mech_cluster_2_missing_or_insufficient_path_validation_for_file_and_resource_access",
  "guideline_id": "gl_mech_0017",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 30 historical CVE example(s), not as a project-specific signature. A safe implementation should add the required guard and bind it to the exact sensitive effect.",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_2_missing_or_insufficient_path_validation_for_file_and_resource_access",
    "name": "Missing or insufficient path validation for file and resource access"
  },
  "structural_sanity": {
    "assigned_case_count": 5,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "mixed_hcvr",
      "pending_review"
    ],
    "metadata_cve_count": 5,
    "primary_hcvr_majority": "path_archive_traversal",
    "primary_hcvr_purity": 0.6,
    "source_cve_count": 30
  }
}