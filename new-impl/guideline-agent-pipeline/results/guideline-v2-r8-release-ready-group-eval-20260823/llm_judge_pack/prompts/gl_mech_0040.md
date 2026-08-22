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
          "end_line": 148,
          "file": "ballcat-codegen-backend/src/main/java/com/hccake/ballcat/codegen/service/impl/GeneratorServiceImpl.java",
          "span_kind": "phase21_011_review_entry_window",
          "start_line": 123,
          "symbol": "GeneratorServiceImpl.generatorCode"
        },
        {
          "end_line": 41,
          "file": "ballcat-codegen-backend/src/main/java/com/hccake/ballcat/codegen/engine/VelocityTemplateEngine.java",
          "span_kind": "phase21_011_review_entry_window",
          "start_line": 21,
          "symbol": "VelocityTemplateEngine.render"
        },
        {
          "end_line": 45,
          "file": "ballcat-codegen-backend/src/main/java/com/hccake/ballcat/codegen/engine/FreemarkerTemplateEngine.java",
          "span_kind": "phase21_011_review_entry_window",
          "start_line": 21,
          "symbol": "FreemarkerTemplateEngine.render"
        }
      ],
      "case_id": "case::ef512b6f2eb40fb85b6d",
      "cve_ids": [
        "CVE-2022-24881"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "ballcat_projects__ballcat_codegen::CVE-2022-24881",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21.011 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 13,
          "file": "browserup-proxy-rest/src/main/java/com/browserup/bup/rest/validation/LongPositiveConstraint.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 8,
          "symbol": ""
        },
        {
          "end_line": 52,
          "file": "browserup-proxy-rest/src/main/java/com/browserup/bup/rest/validation/LongPositiveConstraint.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 41,
          "symbol": ""
        },
        {
          "end_line": 62,
          "file": "browserup-proxy-rest/src/main/java/com/browserup/bup/rest/validation/LongPositiveConstraint.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 59,
          "symbol": ""
        }
      ],
      "case_id": "case::ed14bed7308b3aa49281",
      "cve_ids": [
        "CVE-2020-26282"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "browserup__browserup-proxy::CVE-2020-26282",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 22,
          "file": "spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/DingTalkNotifier.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 17,
          "symbol": ""
        },
        {
          "end_line": 35,
          "file": "spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/DingTalkNotifier.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 29,
          "symbol": ""
        },
        {
          "end_line": 108,
          "file": "spring-boot-admin-server/src/main/java/de/codecentric/boot/admin/server/notify/DingTalkNotifier.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 101,
          "symbol": ""
        }
      ],
      "case_id": "case::250b945c71ad0276342c",
      "cve_ids": [
        "CVE-2022-46166"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "codecentric__spring-boot-admin::CVE-2022-46166",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 12,
          "file": "dropwizard-validation/src/main/java/io/dropwizard/validation/selfvalidating/SelfValidating.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 7,
          "symbol": ""
        },
        {
          "end_line": 27,
          "file": "dropwizard-validation/src/main/java/io/dropwizard/validation/selfvalidating/SelfValidating.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 24,
          "symbol": ""
        },
        {
          "end_line": 45,
          "file": "dropwizard-validation/src/main/java/io/dropwizard/validation/selfvalidating/SelfValidatingValidator.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 31,
          "symbol": ""
        }
      ],
      "case_id": "case::68cb7c73aac71b86d3aa",
      "cve_ids": [
        "CVE-2020-11002"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dropwizard__dropwizard::CVE-2020-11002",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 12,
          "file": "dropwizard-validation/src/main/java/io/dropwizard/validation/selfvalidating/ViolationCollector.java",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 30,
          "file": "dropwizard-validation/src/main/java/io/dropwizard/validation/selfvalidating/ViolationCollector.java",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 17,
          "symbol": ""
        }
      ],
      "case_id": "case::9114418c3137b5b7e079",
      "cve_ids": [
        "CVE-2020-5245"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dropwizard__dropwizard::CVE-2020-5245",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 18,
          "file": "engine/src/main/java/org/hibernate/validator/BaseHibernateValidatorConfiguration.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 13,
          "symbol": ""
        },
        {
          "end_line": 29,
          "file": "engine/src/main/java/org/hibernate/validator/BaseHibernateValidatorConfiguration.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 24,
          "symbol": ""
        },
        {
          "end_line": 149,
          "file": "engine/src/main/java/org/hibernate/validator/BaseHibernateValidatorConfiguration.java",
          "span_kind": "phase21_005_review_entry_window",
          "start_line": 144,
          "symbol": ""
        }
      ],
      "case_id": "case::a915888a199835002d1d",
      "cve_ids": [
        "CVE-2025-35036"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hibernate__hibernate-validator::CVE-2025-35036",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 7,
          "file": "src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 2,
          "symbol": ""
        },
        {
          "end_line": 117,
          "file": "src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 111,
          "symbol": ""
        }
      ],
      "case_id": "case::24d973ef497fbff70389",
      "cve_ids": [
        "CVE-2020-12668"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hubspot__jinjava::CVE-2020-12668",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 84,
          "file": "src/main/java/com/hubspot/jinjava/el/ext/JinjavaBeanELResolver.java",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 79,
          "symbol": ""
        }
      ],
      "case_id": "case::17d33f3743536967af66",
      "cve_ids": [
        "CVE-2025-59340"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hubspot__jinjava::CVE-2025-59340",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "A collection of vulnerabilities where user-controlled input is passed to a template engine or expression language evaluator without proper sanitization, escaping, or restriction of dangerous features, allowing injection of arbitrary expressions that can lead to code execution, file access, or information disclosure.",
  "guideline_group_key": "cluster_0019__mech_template_expression_untrusted_eval",
  "guideline_id": "gl_mech_0040",
  "guideline_text": "Trace attacker-controlled template text, expression strings, macro content, or rendering parameters into template engines, expression evaluators, macro renderers, or scriptable configuration evaluators. Report code paths where untrusted expression content is evaluated without sandboxing, escaping, allowlisting, or disabling reflective execution features. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 16 historical CVE example(s), not as a project-specific signature. A safe implementation should separate data from templates, sandbox expression evaluation, and disable reflection or method invocation features for untrusted input.",
  "judge_selection_reason": "clean_control",
  "mechanism": {
    "family": "code_or_template_injection",
    "mechanism_id": "mech_template_expression_untrusted_eval",
    "name": "untrusted template or expression evaluation"
  },
  "structural_sanity": {
    "assigned_case_count": 10,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [],
    "metadata_cve_count": 10,
    "primary_hcvr_majority": "template_expression_injection",
    "primary_hcvr_purity": 0.8,
    "source_cve_count": 16
  }
}