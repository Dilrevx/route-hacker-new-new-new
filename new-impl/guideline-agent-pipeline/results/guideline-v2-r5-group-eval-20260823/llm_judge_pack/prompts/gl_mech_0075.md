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
          "end_line": 61,
          "file": "src/main/java/com/rtds/svc/CaptureTypeService.java",
          "span_kind": "phase21_016_review_entry_window",
          "start_line": 46,
          "symbol": "CaptureTypeService.findFilter"
        },
        {
          "end_line": 150,
          "file": "src/main/java/com/rtds/PacketCaptureResource.java",
          "span_kind": "method",
          "start_line": 72,
          "symbol": "startTypedCapture"
        },
        {
          "end_line": 61,
          "file": "src/main/java/com/rtds/svc/CaptureTypeService.java",
          "span_kind": "method",
          "start_line": 46,
          "symbol": "findFilter"
        },
        {
          "end_line": 65,
          "file": "src/main/java/com/rtds/svc/CaptureTypeService.java",
          "span_kind": "method",
          "start_line": 46,
          "symbol": "findFilter"
        }
      ],
      "case_id": "case::c5e6aa9d84f13fd8454b",
      "cve_ids": [
        "CVE-2021-39196"
      ],
      "cwe_ids": [
        "CWE-287"
      ],
      "identity_key": "jdhwpgmbca__pcapture::CVE-2021-39196",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "findFilter函数中在处理未定义类型的url时会直接返回null，而非抛出异常，导致权限可能被放宽。 修改后代码 ''' if( type == null ) { throw new IllegalArgumentException( \"The url_suffix must exist in the database.\" ); } // It is okay for the capture filter itself to be null, but the CaptureType // must be in the database, otherwise the user could effectively forge // a capture filter for \"all\" just by requesting a non-existent filter. return type.getCaptureFilter(); '''",
        "Phase 21.016 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": "pcapture is an open source dumpcap web service interface . In affected versions this vulnerability allows an authenticated but unprivileged user to use the REST API to capture and download packets with no capture filter and without adequate permissions. This is important because the capture filters can effectively limit the scope of information that a user can see in the data captures. If no filter is present, then all data on the local network segment where the program is running can be captured and downloaded. v3.12 fixes this problem. There is no workaround, you must upgrade to v3.12 or greater."
    }
  ],
  "cluster_summary": "This cluster contains vulnerabilities stemming from improper handling of user-controllable data in LDAP operations, including missing or incorrect escaping in LDAP filter construction, unbounded recursion during alias dereferencing, credential disclosure in logs, and cross-site scripting via LDAP attribute values. Two outliers involve unrelated SQL injection and database validation bypass.",
  "guideline_group_key": "cluster_0015__mech_jndi_untrusted_lookup_target",
  "guideline_id": "gl_mech_0075",
  "guideline_text": "Trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs. Report code paths where the lookup scheme, authority, object factory, object type, and network destination are not constrained before lookup. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 3 historical CVE example(s), not as a project-specific signature. A safe implementation should bind lookup inputs to trusted constants or allowlists, restrict schemes and destinations, and disable remote object factories.",
  "mechanism": {
    "family": "remote_lookup_or_ssrf",
    "mechanism_id": "mech_jndi_untrusted_lookup_target",
    "name": "attacker-controlled JNDI lookup target"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "CWE-287",
    "cwe_purity": 0.5,
    "flags": [
      "mixed_hcvr",
      "mixed_cwe"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 3
  }
}