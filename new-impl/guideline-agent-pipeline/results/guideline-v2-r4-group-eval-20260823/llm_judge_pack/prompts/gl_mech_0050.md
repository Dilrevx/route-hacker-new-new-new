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
          "end_line": 112,
          "file": "axis-rt-core/src/main/java/org/apache/axis/client/ServiceFactory.java",
          "span_kind": "method_hunk",
          "start_line": 107,
          "symbol": "ServiceFactory.getService.jndiNameProtocolFilter"
        },
        {
          "end_line": 124,
          "file": "axis-rt-core/src/main/java/org/apache/axis/client/ServiceFactory.java",
          "span_kind": "method_hunk",
          "start_line": 119,
          "symbol": "ServiceFactory.getService.contextLookup"
        },
        {
          "end_line": 96,
          "file": "axis-rt-core/src/main/java/org/apache/axis/client/ServiceFactory.java",
          "span_kind": "file_region",
          "start_line": 94,
          "symbol": "ServiceFactory.getService.initialContext.center_window_3"
        },
        {
          "end_line": 97,
          "file": "axis-rt-core/src/main/java/org/apache/axis/client/ServiceFactory.java",
          "span_kind": "file_region",
          "start_line": 93,
          "symbol": "ServiceFactory.getService.initialContext.center_window_5"
        },
        {
          "end_line": 98,
          "file": "axis-rt-core/src/main/java/org/apache/axis/client/ServiceFactory.java",
          "span_kind": "file_region",
          "start_line": 92,
          "symbol": "ServiceFactory.getService.initialContext.center_window_7"
        }
      ],
      "case_id": "case::35fda24b99685065078d",
      "cve_ids": [
        "CVE-2023-51441"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "apache__axis-axis1-java::CVE-2023-51441",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "getService(Map environment) obtains configuration and creates a new InitialContext when JNDI is available. This establishes the JNDI lookup context used by the vulnerable path.",
        "The vulnerable source reads environment[jndiName] and applies an incomplete substring protocol denylist. The reviewed snapshot blocks LDAP/RMI/JMS/JMX/JRMP/JAVA/DNS but does not block IIOP or CORBANAME, which the public fix later adds.",
        "After the incomplete filter, the same user-controlled jndiName is used as the lookup target in context.lookup(name). If lookup fails, the code creates and binds a Service under that name, confirming that jndiName drives JNDI interaction."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 35,
          "file": "core/core-backend/src/main/java/io/dataease/datasource/type/Impala.java",
          "span_kind": "phase21_012_review_entry_window",
          "start_line": 9,
          "symbol": "Impala.getJdbc"
        },
        {
          "end_line": 55,
          "file": "core/core-backend/src/main/java/io/dataease/datasource/type/Db2.java",
          "span_kind": "phase21_012_review_entry_window",
          "start_line": 17,
          "symbol": "Db2.getJdbc"
        }
      ],
      "case_id": "case::7eeb60a6ceb546bfbc10",
      "cve_ids": [
        "CVE-2025-58045"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dataease__dataease::CVE-2025-58045",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.012 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers injection vulnerabilities (JDBC parameter injection, JNDI scheme injection, SQL injection) caused by incomplete blacklists, missing scheme or prefix validation, or direct string concatenation of user input into sensitive constructs. The majority of issues stem from assuming user-controlled data is safe when building JDBC URLs or SQL queries without proper validation, canonicalization, or parameterization.",
  "guideline_group_key": "cluster_0011__mech_jndi_untrusted_lookup_target",
  "guideline_id": "gl_mech_0050",
  "guideline_text": "Trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs. Report code paths where the lookup scheme, authority, object factory, object type, and network destination are not constrained before lookup. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 12 historical CVE example(s), not as a project-specific signature. A safe implementation should bind lookup inputs to trusted constants or allowlists, restrict schemes and destinations, and disable remote object factories.",
  "mechanism": {
    "family": "remote_lookup_or_ssrf",
    "mechanism_id": "mech_jndi_untrusted_lookup_target",
    "name": "attacker-controlled JNDI lookup target"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 12
  }
}