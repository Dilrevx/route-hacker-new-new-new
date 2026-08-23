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
    "boundary_label": "candidate_boundary_03_spel_context",
    "boundary_text": "SpEL unrestricted evaluation context: attacker-influenced notification, template, or expression content is evaluated with Spring Expression Language using StandardEvaluationContext or another context that permits method invocation, type access, or broad property access. Report flows where the expression evaluation context is not reduced to read-only property/data binding access before evaluation.",
    "evidence_refs": [
      {
        "identity_key": "codecentric__spring-boot-admin::CVE-2022-46166",
        "source_evidence": "Fix commit c14c3ec12533f71f84de9ce3ce5ceb7991975f75 changes DingTalk, Discord, Hipchat, and LetsChat notifier rendering from StandardEvaluationContext plus MapAccessor to SimpleEvaluationContext.forPropertyAccessors(DataBindingPropertyAccessor.forReadOnlyAccess(), new MapAccessor()).withRootObject(root).build()."
      },
      {
        "identity_key": "codecentric__spring-boot-admin::CVE-2022-46166",
        "source_evidence": "The patch location and replacement API identify the vulnerable sink as SpEL expression rendering in notifier templates and the missing guard as an overly powerful evaluation context rather than output escaping."
      }
    ],
    "exploit_precondition": "An attacker can influence notification template content, evaluated expression content, or data fields that reach the notifier's SpEL rendering path, and the server renders those expressions in the vulnerable StandardEvaluationContext.",
    "guideline_id": "gl_mech_0040",
    "mechanism_id": "mech_spel_unrestricted_evaluation_context",
    "mechanism_name": "SpEL evaluation with unrestricted StandardEvaluationContext",
    "missing_guard": "The vulnerable notifier rendering path does not restrict the SpEL context to read-only data binding/property access on the same evaluation path. StandardEvaluationContext is too permissive for untrusted or attacker-influenced expressions.",
    "rationale": "The patch directly replaces a permissive SpEL evaluation context with a restricted SimpleEvaluationContext on the vulnerable rendering path, supporting this narrow guideline boundary.",
    "recall_follow_up": "After a sidecar change, rerun same-identity recall for codecentric__spring-boot-admin::CVE-2022-46166 and inspect whether candidate windows include notifier render methods and StandardEvaluationContext/SimpleEvaluationContext symbols.",
    "representative_cases": [
      "codecentric__spring-boot-admin::CVE-2022-46166"
    ],
    "reviewer_notes": "This is a single-case but clean SpEL-specific boundary. It should not be merged with Bean Validation message interpolation or Jinjava property resolution because the sink and fix are Spring SpEL evaluation-context selection.",
    "safe_fix_semantics": "Replace StandardEvaluationContext on the affected rendering path with SimpleEvaluationContext.forPropertyAccessors(DataBindingPropertyAccessor.forReadOnlyAccess(), new MapAccessor()).withRootObject(root).build(), or an equivalent restricted context that only exposes intended read-only data properties before evaluation.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "SpEL evaluation over notification data with StandardEvaluationContext can expose method invocation or broader object access than intended, allowing untrusted template/expression content to execute or inspect unsafe operations during notification rendering.",
    "source_shape": "The reviewed Spring Boot Admin notifier path renders notification templates or expression-backed message fields against a root data object. The vulnerable code used StandardEvaluationContext with MapAccessor in multiple notifiers."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.