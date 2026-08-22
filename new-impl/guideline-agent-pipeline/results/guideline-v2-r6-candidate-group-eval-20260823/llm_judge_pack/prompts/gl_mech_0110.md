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
          "end_line": 30,
          "file": "src/main/java/cd/go/apacheds/ApacheDsLdapClient.java",
          "span_kind": "hunk",
          "start_line": 25,
          "symbol": ""
        },
        {
          "end_line": 77,
          "file": "src/main/java/cd/go/framework/ldap/JNDILdapClient.java",
          "span_kind": "hunk",
          "start_line": 71,
          "symbol": ""
        },
        {
          "end_line": 101,
          "file": "src/main/java/cd/go/apacheds/ApacheDsLdapClient.java",
          "span_kind": "hunk",
          "start_line": 95,
          "symbol": ""
        },
        {
          "end_line": 30,
          "file": "src/main/java/cd/go/authentication/ldap/LdapClient.java",
          "span_kind": "hunk",
          "start_line": 24,
          "symbol": ""
        },
        {
          "end_line": 115,
          "file": "src/main/java/cd/go/apacheds/ApacheDsLdapClient.java",
          "span_kind": "hunk",
          "start_line": 109,
          "symbol": ""
        }
      ],
      "case_id": "case::342b5bc8e77a63b32ac3",
      "cve_ids": [
        "CVE-2022-24832"
      ],
      "cwe_ids": [
        "CWE-74"
      ],
      "identity_key": "gocd__gocd-ldap-authentication-plugin::CVE-2022-24832",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 213,
          "file": "opendj-server-legacy/src/main/java/org/opends/server/workflowelement/localbackend/LocalBackendSearchOperation.java",
          "span_kind": "primary_opendj_unguarded_alias_dereference_recursion_anchor",
          "start_line": 202,
          "symbol": "LocalBackendSearchOperation alias dereference recursion"
        },
        {
          "end_line": 207,
          "file": "opendj-server-legacy/src/main/java/org/opends/server/workflowelement/localbackend/LocalBackendSearchOperation.java",
          "span_kind": "alias_deref_policy_condition_anchor",
          "start_line": 204,
          "symbol": "LocalBackendSearchOperation dereference policy condition"
        },
        {
          "end_line": 309,
          "file": "opendj-server-legacy/src/test/java/org/openidentityplatform/opendj/AliasTestCase.java",
          "span_kind": "pre_fix_alias_always_test_gap_anchor",
          "start_line": 301,
          "symbol": "AliasTestCase.test_sub_always"
        }
      ],
      "case_id": "case::cda957aed92a2f50306f",
      "cve_ids": [
        "CVE-2025-27497"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "openidentityplatform__opendj::CVE-2025-27497",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "Local backend search processing initializes backend and client state and invokes processSearch, the recursive search routine affected by alias dereferencing.",
        "processSearch is the private routine that recursively re-enters itself when dereferencing alias base entries.",
        "The vulnerable code enables alias dereferencing for ALWAYS, FINDING_BASE, and subtree IN_SEARCHING policies, matching the advisory condition."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster contains vulnerabilities where user-controlled input is incorporated into LDAP search filters or distinguished names without proper escaping of special characters, allowing LDAP injection attacks. The majority of cases lack any escaping mechanism, while one case uses an inappropriate encoding (DN encoding) that fails to neutralize filter metacharacters. Two outliers involve unrelated vulnerabilities: credential leakage in logs and unbounded recursion in alias resolution.",
  "guideline_group_key": "cluster_0024__mech_ldap_filter_unescaped_input",
  "guideline_id": "gl_mech_0110",
  "guideline_text": "Trace attacker-controlled usernames, account names, directory attributes, filter fragments, distinguished names, or LDAP query parameters into LDAP search filters, distinguished-name construction, directory queries, or LDAP bind/search operations. Report code paths where LDAP metacharacters and distinguished-name syntax are not escaped or parameterized for the exact LDAP context before the query. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 10 historical CVE example(s), not as a project-specific signature. A safe implementation should use context-specific LDAP filter or DN escaping, parameterized filter construction where available, and allowlist structural query fragments.",
  "mechanism": {
    "family": "directory_query_injection",
    "mechanism_id": "mech_ldap_filter_unescaped_input",
    "name": "LDAP filter or distinguished-name injection through unescaped input"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "CWE-74",
    "cwe_purity": 0.5,
    "flags": [
      "mixed_hcvr",
      "mixed_cwe"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 10
  }
}