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
          "end_line": 161,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "function",
          "start_line": 142,
          "symbol": "CommonServiceImpl.urlDownload"
        },
        {
          "end_line": 161,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "function",
          "start_line": 146,
          "symbol": "CommonServiceImpl.urlDownload"
        },
        {
          "end_line": 185,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "function",
          "start_line": 159,
          "symbol": "CommonServiceImpl.urlDownload"
        },
        {
          "end_line": 160,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "sliding_window",
          "start_line": 81,
          "symbol": "CommonServiceImpl.urlDownload"
        },
        {
          "end_line": 200,
          "file": "sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java",
          "span_kind": "sliding_window",
          "start_line": 121,
          "symbol": "CommonServiceImpl.urlDownload"
        }
      ],
      "case_id": "case::84a39bdc311e873b9594",
      "cve_ids": [
        "CVE-2026-3189"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "feiyuchuixue__sz-boot-parent::CVE-2026-3189",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Manual repair confirms an SSRF source-to-sink contract in CommonServiceImpl.urlDownload: caller-controlled URL material is preserved as fileUrl and reaches Java URL.openStream on the server side. The patch adds URL parsing and an http/https-only protocol guard before openStream. This checkpoint repairs metadata only; it does not add labels, run retrieval, or claim dynamic exploit proof.",
        "tempDownload fetches a stored UploadResult URL or private OSS URL with new URL(fileUrl).openStream(). It is retained as SSRF-adjacent fetch context, but lower priority than urlDownload because the URL is loaded from stored file metadata rather than directly from this method's request parameter.",
        "These helpers parse http(s) URLs into bucket/object components used by urlDownload and private URL generation. They are useful review-entry context because parsing policy constrains what target the server eventually fetches."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities where user-controlled input is used to construct file paths or resource identifiers without proper validation, canonicalization, or containment checks, enabling directory traversal, unauthorized file read/write, or resource access. A minority of outliers involve unrelated vulnerabilities like deserialization, SSRF, regular expression injection, and stored XSS.",
  "guideline_group_key": "cluster_0002__mech_ssrf_webhook_url_fetch",
  "guideline_id": "gl_mech_0007",
  "guideline_text": "Trace attacker-controlled webhook URLs, callback URLs, endpoint parameters, or request destinations into outbound HTTP clients, URL.openConnection, fetch helpers, proxy clients, or webhook dispatchers. Report code paths where scheme, host, redirect target, DNS resolution, and private-address ranges are not constrained before the outbound request. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 4 historical CVE example(s), not as a project-specific signature. A safe implementation should enforce scheme and host allowlists, block private and metadata addresses after DNS resolution, and validate redirect targets.",
  "judge_selection_reason": "small_group",
  "mechanism": {
    "family": "ssrf",
    "mechanism_id": "mech_ssrf_webhook_url_fetch",
    "name": "attacker-controlled webhook or callback URL fetch"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "small_group"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "ssrf",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 4
  }
}