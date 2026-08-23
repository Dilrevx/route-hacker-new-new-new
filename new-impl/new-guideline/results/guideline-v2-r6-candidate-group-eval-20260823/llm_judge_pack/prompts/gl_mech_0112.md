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
          "end_line": 134,
          "file": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java",
          "span_kind": "hunk",
          "start_line": 132,
          "symbol": ""
        },
        {
          "end_line": 135,
          "file": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java",
          "span_kind": "file_region",
          "start_line": 131,
          "symbol": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java:132-134.center_window_5"
        },
        {
          "end_line": 136,
          "file": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java",
          "span_kind": "file_region",
          "start_line": 130,
          "symbol": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java:132-134.center_window_7"
        },
        {
          "end_line": 138,
          "file": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java",
          "span_kind": "file_region",
          "start_line": 128,
          "symbol": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java:132-134.center_window_11"
        },
        {
          "end_line": 140,
          "file": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java",
          "span_kind": "file_region",
          "start_line": 126,
          "symbol": "para-server/src/main/java/com/erudika/para/server/utils/HealthUtils.java:132-134.center_window_15"
        }
      ],
      "case_id": "case::80f9a438c17160e6e45a",
      "cve_ids": [
        "CVE-2025-48955"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "erudika__para::CVE-2025-48955",
      "primary_hcvr_type": "iris",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 1341,
          "file": "src/main/java/net/snowflake/client/jdbc/SnowflakeFileTransferAgent.java",
          "span_kind": "primary_debug_response_encryption_material_leak_anchor",
          "start_line": 1339,
          "symbol": "SnowflakeFileTransferAgent.parseCommandInGS response debug log"
        },
        {
          "end_line": 224,
          "file": "src/main/java/net/snowflake/client/jdbc/SnowflakeFileTransferAgent.java",
          "span_kind": "primary_encryption_material_json_anchor",
          "start_line": 204,
          "symbol": "SnowflakeFileTransferAgent.getEncryptionMaterial(CommandType, JsonNode)"
        },
        {
          "end_line": 158,
          "file": "src/main/java/net/snowflake/client/jdbc/cloud/storage/EncryptionProvider.java",
          "span_kind": "client_side_master_key_usage_anchor",
          "start_line": 147,
          "symbol": "EncryptionProvider.encrypt(...) queryStageMasterKey use"
        }
      ],
      "case_id": "case::27911f1968b85b43947f",
      "cve_ids": [
        "CVE-2025-27496"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "snowflakedb__snowflake-jdbc::CVE-2025-27496",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The base file transfer contract states GET/PUT commands are parsed before execution and that implementations populate encryption-related file-transfer state.",
        "The vulnerable sink logs the complete GS JsonNode response at DEBUG level with jsonNode.toString() before any masking specific to encryptionMaterial is applied.",
        "The same JsonNode returned by parseCommandInGS drives GET/PUT parsing and is passed to initEncryptionMaterial(), connecting the logged response to encryption material extraction."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "The cluster involves vulnerabilities where code logs or propagates error messages without sanitizing or redacting sensitive data, leading to information disclosure or log injection.",
  "guideline_group_key": "cluster_0025__pending_mech_cluster_25_information_leakage_due_to_missing_redaction",
  "guideline_id": "gl_mech_0112",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 4 historical CVE example(s), not as a project-specific signature. A safe implementation should Apply redaction functions to remove or replace sensitive data before logging or before throwing exceptions..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_25_information_leakage_due_to_missing_redaction",
    "name": "Information leakage due to missing redaction"
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
    "source_cve_count": 4
  }
}