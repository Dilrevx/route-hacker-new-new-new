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
          "end_line": 318,
          "file": "src/DBManager.java",
          "span_kind": "hunk",
          "start_line": 151,
          "symbol": ""
        },
        {
          "end_line": 442,
          "file": "src/DBManager.java",
          "span_kind": "hunk",
          "start_line": 404,
          "symbol": ""
        },
        {
          "end_line": 11,
          "file": "src/DBManager.java",
          "span_kind": "hunk",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 577,
          "file": "src/DBManager.java",
          "span_kind": "hunk",
          "start_line": 570,
          "symbol": ""
        },
        {
          "end_line": 48,
          "file": "src/DBManager.java",
          "span_kind": "hunk",
          "start_line": 41,
          "symbol": ""
        }
      ],
      "case_id": "case::55f86f764b5a18b834d6",
      "cve_ids": [
        "CVE-2015-10047"
      ],
      "cwe_ids": [
        "CWE-89"
      ],
      "identity_key": "kyuubl__school-register::CVE-2015-10047",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 42,
          "file": "HeatMapServer/src/com/datformers/servlet/HeatMapServlet.java",
          "span_kind": "hunk",
          "start_line": 36,
          "symbol": ""
        },
        {
          "end_line": 31,
          "file": "HeatMapServer/src/com/datformers/servlet/AddAppUser.java",
          "span_kind": "hunk",
          "start_line": 25,
          "symbol": ""
        },
        {
          "end_line": 6,
          "file": "HeatMapServer/src/com/datformers/database/OracleDBWrapper.java",
          "span_kind": "hunk",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 10,
          "file": "HeatMapServer/src/com/datformers/servlet/LoginServlet.java",
          "span_kind": "hunk",
          "start_line": 5,
          "symbol": ""
        },
        {
          "end_line": 22,
          "file": "HeatMapServer/src/com/datformers/servlet/AddAppUser.java",
          "span_kind": "hunk",
          "start_line": 6,
          "symbol": ""
        }
      ],
      "case_id": "case::752006c3d7859db2c724",
      "cve_ids": [
        "CVE-2015-10020"
      ],
      "cwe_ids": [
        "CWE-89"
      ],
      "identity_key": "ssn2013__cis450project::CVE-2015-10020",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 118,
          "file": "src/com/bezman/servlet/MonthlyRecapServlet.java",
          "span_kind": "hunk",
          "start_line": 111,
          "symbol": ""
        },
        {
          "end_line": 88,
          "file": "src/com/bezman/servlet/ItemRecapServlet.java",
          "span_kind": "hunk",
          "start_line": 63,
          "symbol": ""
        },
        {
          "end_line": 79,
          "file": "src/com/bezman/servlet/DailyServlet.java",
          "span_kind": "hunk",
          "start_line": 72,
          "symbol": ""
        },
        {
          "end_line": 17,
          "file": "src/com/bezman/servlet/DailyServlet.java",
          "span_kind": "hunk",
          "start_line": 10,
          "symbol": ""
        },
        {
          "end_line": 96,
          "file": "src/com/bezman/servlet/StudentSettingsServlet.java",
          "span_kind": "hunk",
          "start_line": 90,
          "symbol": ""
        }
      ],
      "case_id": "case::75d616ccf7ce1c78e278",
      "cve_ids": [
        "CVE-2014-125047"
      ],
      "cwe_ids": [
        "CWE-89"
      ],
      "identity_key": "tbezman__school-store::CVE-2014-125047",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "A set of SQL injection vulnerabilities where user-controlled input is concatenated directly into SQL query strings without using parameterized queries, prepared statements, or proper escaping, allowing attackers to inject arbitrary SQL commands.",
  "guideline_group_key": "cluster_0013__pending_mech_cluster_13_direct_string_concatenation_into_sql_query",
  "guideline_id": "gl_mech_0068",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 12 historical CVE example(s), not as a project-specific signature. A safe implementation should Replace string concatenation with parameterized queries using placeholders (?, :name) and binding methods such as setString(), setInt(), setObject(), or ORM-specific equivalents like Ebean Expr.eq or JPQL setParameter..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_13_direct_string_concatenation_into_sql_query",
    "name": "Direct string concatenation into SQL query"
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
    "source_cve_count": 12
  }
}