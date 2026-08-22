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
          "end_line": 42,
          "file": "dashbuilder-backend/dashbuilder-dataset-sql/src/test/java/org/dashbuilder/dataprovider/sql/SQLTestSuite.java",
          "span_kind": "hunk",
          "start_line": 37,
          "symbol": ""
        },
        {
          "end_line": 551,
          "file": "dashbuilder-backend/dashbuilder-dataset-sql/src/main/java/org/dashbuilder/dataprovider/sql/dialect/DefaultDialect.java",
          "span_kind": "hunk",
          "start_line": 545,
          "symbol": ""
        }
      ],
      "case_id": "case::a3a7f50b801343330613",
      "cve_ids": [
        "CVE-2016-4999"
      ],
      "cwe_ids": [
        "CWE-89"
      ],
      "identity_key": "dashbuilder__dashbuilder::CVE-2016-4999",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 50,
          "file": "dhis-2/dhis-support/dhis-support-system/src/main/java/org/hisp/dhis/system/util/SqlUtils.java",
          "span_kind": "hunk",
          "start_line": 45,
          "symbol": ""
        },
        {
          "end_line": 62,
          "file": "dhis-2/dhis-support/dhis-support-commons/src/main/java/org/hisp/dhis/commons/collection/CollectionUtils.java",
          "span_kind": "hunk",
          "start_line": 57,
          "symbol": ""
        },
        {
          "end_line": 39,
          "file": "dhis-2/dhis-services/dhis-service-core/src/main/java/org/hisp/dhis/association/ProgramOrganisationUnitAssociationsQueryBuilder.java",
          "span_kind": "hunk",
          "start_line": 34,
          "symbol": ""
        },
        {
          "end_line": 48,
          "file": "dhis-2/dhis-services/dhis-service-core/src/main/java/org/hisp/dhis/association/ProgramOrganisationUnitAssociationsQueryBuilder.java",
          "span_kind": "hunk",
          "start_line": 43,
          "symbol": ""
        },
        {
          "end_line": 179,
          "file": "dhis-2/dhis-services/dhis-service-core/src/main/java/org/hisp/dhis/association/ProgramOrganisationUnitAssociationsQueryBuilder.java",
          "span_kind": "hunk",
          "start_line": 173,
          "symbol": ""
        }
      ],
      "case_id": "case::48d0a26cb0142506a751",
      "cve_ids": [
        "CVE-2022-24848"
      ],
      "cwe_ids": [
        "CWE-89"
      ],
      "identity_key": "dhis2__dhis2-core::CVE-2022-24848",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 39,
          "file": "src/community/jdbcconfig/src/test/java/org/geoserver/jdbcconfig/internal/QueryBuilderTest.java",
          "span_kind": "hunk",
          "start_line": 27,
          "symbol": ""
        },
        {
          "end_line": 32,
          "file": "src/community/jdbcconfig/src/main/java/org/geoserver/jdbcconfig/internal/OracleDialect.java",
          "span_kind": "hunk",
          "start_line": 21,
          "symbol": ""
        },
        {
          "end_line": 422,
          "file": "src/community/jdbcconfig/src/main/java/org/geoserver/jdbcconfig/internal/FilterToCatalogSQL.java",
          "span_kind": "hunk",
          "start_line": 360,
          "symbol": ""
        },
        {
          "end_line": 233,
          "file": "src/community/jdbcconfig/src/main/java/org/geoserver/jdbcconfig/internal/ConfigDatabase.java",
          "span_kind": "hunk",
          "start_line": 227,
          "symbol": ""
        },
        {
          "end_line": 302,
          "file": "src/community/jdbcconfig/src/main/java/org/geoserver/jdbcconfig/internal/ConfigDatabase.java",
          "span_kind": "hunk",
          "start_line": 296,
          "symbol": ""
        }
      ],
      "case_id": "case::ffe7a6bf178689d98d59",
      "cve_ids": [
        "CVE-2023-25157"
      ],
      "cwe_ids": [
        "CWE-89"
      ],
      "identity_key": "geoserver__geoserver::CVE-2023-25157",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "Multiple vulnerabilities arise from user-controlled input being concatenated directly into SQL query strings without proper escaping or use of parameterized queries, leading to SQL injection. A few related issues involve regex backtracking, OS command injection, and Elasticsearch query malformation causing denial of service.",
  "guideline_group_key": "cluster_0014__pending_mech_cluster_14_sql_injection_mitigated_by_input_escaping",
  "guideline_id": "gl_mech_0073",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 4 historical CVE example(s), not as a project-specific signature. A safe implementation should Escape special characters (single quotes by doubling, comment delimiters by backslash) or apply blacklist filtering before concatenation..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_14_sql_injection_mitigated_by_input_escaping",
    "name": "SQL injection mitigated by input escaping"
  },
  "structural_sanity": {
    "assigned_case_count": 3,
    "cwe_majority": "CWE-89",
    "cwe_purity": 1.0,
    "flags": [
      "pending_review"
    ],
    "metadata_cve_count": 3,
    "primary_hcvr_majority": "unspecified",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 4
  }
}