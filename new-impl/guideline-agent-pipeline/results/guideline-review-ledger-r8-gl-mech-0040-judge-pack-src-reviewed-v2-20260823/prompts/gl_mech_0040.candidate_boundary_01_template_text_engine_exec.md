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

Ledger-specific instructions:
{
  "decision_values": [
    "accept",
    "revise",
    "split",
    "merge",
    "needs_evidence"
  ],
  "expected_json": {
    "actionability_score": 0.0,
    "coherence_score": 0.0,
    "coverage_score": 0.0,
    "decision": "accept|revise|split|merge|needs_evidence",
    "evidence_notes": [
      "case-level evidence or missing evidence"
    ],
    "main_issue": "short explanation",
    "retrieval_query_quality": 0.0,
    "split_suggestions": [
      "submechanism A",
      "submechanism B"
    ],
    "suggested_guideline": "rewrite if decision is revise or split"
  },
  "review_scope": [
    "Judge semantic boundary quality only.",
    "Check whether source shape, sink/effect, missing guard, exploit precondition, and safe fix are coherent.",
    "Check whether representative cases support the boundary decision.",
    "Do not judge embedding recall, known-anchor rank, Top-K metrics, or model performance.",
    "Do not invent new source evidence. If evidence is insufficient, return needs_evidence.",
    "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only."
  ],
  "task": "Review one source-reviewed guideline boundary ledger row."
}

Ledger boundary payload:
{
  "judge_mode": "source_reviewed_boundary_advisory",
  "ledger_row": {
    "boundary_decision": "promote_boundary",
    "boundary_label": "candidate_boundary_01_template_text_engine_exec",
    "boundary_text": "Untrusted template text evaluated by a template engine: attacker-controlled template source text, macro content, or code-generation template content is passed into a template engine such as FreeMarker or Velocity and rendered with a powerful default configuration. Report code paths where the template text itself is untrusted and the engine can resolve classes, invoke methods, or otherwise execute reflective features without a sandbox, safe class resolver, allowlist, or equivalent restriction applied before rendering.",
    "evidence_refs": [
      {
        "identity_key": "ballcat_projects__ballcat_codegen::CVE-2022-24881",
        "source_evidence": "Vulnerable checkout 719dd74cab14c094a483b4ba735fcd3c5cc4058e, ballcat-codegen-backend/src/main/java/com/hccake/ballcat/codegen/service/impl/GeneratorServiceImpl.java:123-148, obtains templateFile.getContent() and passes that content into templateEngineDelegator.render(...)."
      },
      {
        "identity_key": "ballcat_projects__ballcat_codegen::CVE-2022-24881",
        "source_evidence": "The same vulnerable checkout shows ballcat-codegen-backend/src/main/java/com/hccake/ballcat/codegen/engine/VelocityTemplateEngine.java:33-38 calling Velocity.evaluate(..., templateContent), and FreemarkerTemplateEngine.java:33-40 constructing a Template from templateContent and processing it."
      },
      {
        "identity_key": "ballcat_projects__ballcat_codegen::CVE-2022-24881",
        "source_evidence": "Fix commit 84a7cb38daf0295b93aba21d562ec627e4eb463b adds FreeMarker TemplateClassResolver.SAFER_RESOLVER and Velocity SecureUberspector, confirming the missing guard is unsafe template-engine capability exposure rather than a generic output-encoding issue."
      }
    ],
    "exploit_precondition": "An attacker can create or modify template content that the code-generation path renders, or otherwise influence the template source text consumed by the generator. The server then renders that content using FreeMarker or Velocity with privileged default features.",
    "guideline_id": "gl_mech_0040",
    "mechanism_id": "mech_untrusted_template_text_engine_exec",
    "mechanism_name": "untrusted template text evaluated by template engine",
    "missing_guard": "The vulnerable flow lacks a template-engine sandbox or feature restriction on the exact render path. In particular, the old FreeMarker configuration does not install TemplateClassResolver.SAFER_RESOLVER and the old Velocity configuration does not use a SecureUberspector before evaluating templateContent.",
    "rationale": "The source and patch evidence directly show untrusted template text reaching FreeMarker and Velocity render sinks and the fix restricting engine capabilities. This supports a narrow reusable template-engine execution boundary.",
    "recall_follow_up": "After promoting this boundary into recall-consumed text, rerun same-identity recall for ballcat_projects__ballcat_codegen::CVE-2022-24881 and the frozen 143 identity set. If recall misses, inspect query wording around editable template source, engine class resolver, and Velocity/FreeMarker candidate slicing before weakening the semantic boundary.",
    "representative_cases": [
      "ballcat_projects__ballcat_codegen::CVE-2022-24881"
    ],
    "reviewer_notes": "This is the source-template execution subset of the old gl_mech_0040 umbrella. It should remain separate from Bean Validation message interpolation, SpEL notifier template evaluation, and Jinjava sandbox-bypass property resolution because those have different sources, sinks, and fixes.",
    "safe_fix_semantics": "Configure the engine before rendering untrusted template source: FreeMarker should use TemplateClassResolver.SAFER_RESOLVER or an equivalent safe resolver, and Velocity should use a SecureUberspector or equivalent sandbox. The fix must apply to the engine instance used by the vulnerable render call, not merely sanitize downstream output.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "VelocityTemplateEngine.render calls Velocity.evaluate(velocityContext, sw, \"velocityTemplateEngine\", templateContent), and FreemarkerTemplateEngine.render constructs new Template(\"templateName\", templateContent, configuration) followed by template.process(context, sw). Rendering attacker-controlled template source with unrestricted engine features can execute or expose dangerous operations during code generation.",
    "source_shape": "A code-generation service loads editable template content and passes that template string into rendering engines. The reviewed vulnerable source shows GeneratorServiceImpl.generatorCode obtaining templateFile.getContent() and calling templateEngineDelegator.render(...)."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.