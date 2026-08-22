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
          "end_line": 105,
          "file": "modules/jooby-netty/src/main/java/io/jooby/internal/netty/NettyContext.java",
          "span_kind": "hunk",
          "start_line": 99,
          "symbol": ""
        }
      ],
      "case_id": "case::4fd06086a2c3f86a7dc8",
      "cve_ids": [
        "CVE-2020-7622"
      ],
      "cwe_ids": [
        "CWE-444",
        "CWE-74"
      ],
      "identity_key": "jooby-project__jooby::CVE-2020-7622",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 59,
          "file": "http-netty/src/main/java/io/micronaut/http/netty/NettyHttpHeaders.java",
          "span_kind": "hunk",
          "start_line": 53,
          "symbol": ""
        }
      ],
      "case_id": "case::d952c78c9fb0954df558",
      "cve_ids": [
        "CVE-2020-7611"
      ],
      "cwe_ids": [
        "CWE-444"
      ],
      "identity_key": "micronaut-projects__micronaut-core::CVE-2020-7611",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "A collection of vulnerabilities where protocol parsers (HTTP, email, AJP, etc.) fail to validate user-supplied input for control characters, enforce protocol-specific constraints, or limit resource consumption, leading to CRLF injection, request smuggling, denial of service, or email header manipulation.",
  "guideline_group_key": "cluster_0041__pending_mech_cluster_41_crlf_injection_due_to_missing_header_value_validation",
  "guideline_id": "gl_mech_0229",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 15 historical CVE example(s), not as a project-specific signature. A safe implementation should Add validation to reject or strip CR/LF characters in header values, either by enabling built-in validation (e.g., DefaultHttpHeaders with validation) or by adding explicit character checks before header construction..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_41_crlf_injection_due_to_missing_header_value_validation",
    "name": "CRLF injection due to missing header value validation"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "CWE-444",
    "cwe_purity": 0.6667,
    "flags": [
      "mixed_cwe",
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "unspecified",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 15
  }
}