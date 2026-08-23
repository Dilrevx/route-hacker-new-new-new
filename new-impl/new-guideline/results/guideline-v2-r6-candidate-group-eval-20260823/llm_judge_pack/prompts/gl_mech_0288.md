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
          "end_line": 83,
          "file": "xwiki-commons-core/xwiki-commons-velocity/src/main/java/org/xwiki/velocity/introspection/SecureIntrospector.java",
          "span_kind": "primary_file_method_policy_gap_anchor",
          "start_line": 75,
          "symbol": "SecureIntrospector.checkObjectExecutePermission"
        },
        {
          "end_line": 73,
          "file": "xwiki-commons-core/xwiki-commons-velocity/src/main/java/org/xwiki/velocity/introspection/SecureIntrospector.java",
          "span_kind": "missing_file_whitelist_anchor",
          "start_line": 43,
          "symbol": "SecureIntrospector constructor"
        },
        {
          "end_line": 49,
          "file": "xwiki-commons-core/xwiki-commons-velocity/src/main/java/org/xwiki/velocity/introspection/SecureUberspector.java",
          "span_kind": "velocity_secure_introspection_entry_anchor",
          "start_line": 39,
          "symbol": "SecureUberspector.init"
        },
        {
          "end_line": 164,
          "file": "xwiki-commons-core/xwiki-commons-velocity/src/main/java/org/xwiki/velocity/internal/DefaultVelocityConfiguration.java",
          "span_kind": "default_sandbox_registration_anchor",
          "start_line": 142,
          "symbol": "DefaultVelocityConfiguration.initializeDefaultUberspectors"
        },
        {
          "end_line": 29,
          "file": "pom.xml",
          "span_kind": "affected_version_anchor",
          "start_line": 24,
          "symbol": "org.xwiki.commons:xwiki-commons version 12.6.6"
        }
      ],
      "case_id": "case::6415d2d832b2c7add227",
      "cve_ids": [
        "CVE-2022-24897"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "xwiki__xwiki-commons::CVE-2022-24897",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The exact checkout declares XWiki Commons 12.6.6, which is before the advisory patched 12.6.7 release.",
        "The default Velocity configuration installs SecureUberspector first to block dangerous APIs in Velocity scripts.",
        "Velocity runtime initialization applies the configuration properties, including the uberspector chain, before template evaluation."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 1023,
          "file": "xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/api/XWiki.java",
          "span_kind": "phase21_020_review_entry_window",
          "start_line": 1000,
          "symbol": "com.xpn.xwiki.api.XWiki.invokeServletAndReturnAsString"
        },
        {
          "end_line": 2598,
          "file": "xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/XWiki.java",
          "span_kind": "phase21_020_review_entry_window",
          "start_line": 2581,
          "symbol": "com.xpn.xwiki.XWiki.invokeServletAndReturnAsString"
        },
        {
          "end_line": 1012,
          "file": "xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/api/XWiki.java",
          "span_kind": "file_region",
          "start_line": 1010,
          "symbol": "com.xpn.xwiki.api.XWiki.invokeServletAndReturnAsString.center_window_3"
        },
        {
          "end_line": 1013,
          "file": "xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/api/XWiki.java",
          "span_kind": "file_region",
          "start_line": 1009,
          "symbol": "com.xpn.xwiki.api.XWiki.invokeServletAndReturnAsString.center_window_5"
        },
        {
          "end_line": 1014,
          "file": "xwiki-platform-core/xwiki-platform-oldcore/src/main/java/com/xpn/xwiki/api/XWiki.java",
          "span_kind": "file_region",
          "start_line": 1008,
          "symbol": "com.xpn.xwiki.api.XWiki.invokeServletAndReturnAsString.center_window_7"
        }
      ],
      "case_id": "case::1f6c87e555528e5a2072",
      "cve_ids": [
        "CVE-2022-23621"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "xwiki__xwiki_platform::CVE-2022-23621",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "Phase 21.020 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers multiple vulnerabilities in XWiki where dynamic code execution (especially Velocity templates) is performed without proper authorization checks, input validation, or sandbox restrictions. The issues include missing script/programming rights checks, insufficient method-level sandboxing, validation gaps for document origins, and incorrect handling of default content types. Fixes involve adding authorization checks, method whitelists, and proper default values to prevent unauthorized code execution.",
  "guideline_group_key": "cluster_0063__mech_privileged_server_side_capability_exposed",
  "guideline_id": "gl_mech_0288",
  "guideline_text": "Trace lower-privilege script, template, macro, plugin, or API callers that can invoke privileged server-side capabilities into server-side include, template rendering, servlet dispatch, raw object access, internal file reads, or privileged framework APIs. Report code paths where a higher privilege check is not enforced at the API entry point before exposing the server-side capability. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 11 historical CVE example(s), not as a project-specific signature. A safe implementation should check the required higher privilege at the exposed API boundary and return no sensitive result when the caller lacks that privilege.",
  "mechanism": {
    "family": "authorization",
    "mechanism_id": "mech_privileged_server_side_capability_exposed",
    "name": "privileged server-side capability exposed to lower privilege context"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authorization_bypass",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 11
  }
}