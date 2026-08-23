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
    "boundary_label": "candidate_boundary_02_bean_validation_message_el",
    "boundary_text": "Bean Validation message template EL interpolation injection: attacker-controlled validation values, custom messages, or message fragments are embedded into a Bean Validation constraint violation template via buildConstraintViolationWithTemplate or an equivalent EL-capable interpolation sink. Report flows where attacker text containing `{`, `}`, `$`, or `${...}` reaches that template without escaping metacharacters, using message-parameter APIs, or disabling EL interpolation before message rendering.",
    "evidence_refs": [
      {
        "identity_key": "dropwizard__dropwizard::CVE-2020-11002",
        "source_evidence": "Vulnerable ViolationCollector.addViolation at lines 24-27 passes msg directly to context.buildConstraintViolationWithTemplate(msg). Fix commit d5a512f7abf965275f2a6b913ac4fe778e424242 adds InterpolationHelper.escapeMessageParameter, escapeExpressions, message parameter APIs, and sanitized templates."
      },
      {
        "identity_key": "dropwizard__dropwizard::CVE-2020-5245",
        "source_evidence": "Fix commit 28479f743a9d0aab6d0e963fc07f3dd98e8c8236 adds ESCAPE_PATTERN = Pattern.compile(\"\\\\$\\\\{\") and escapeEl, changing buildConstraintViolationWithTemplate(msg) to use escaped message content."
      },
      {
        "identity_key": "browserup__browserup-proxy::CVE-2020-26282",
        "source_evidence": "Vulnerable LongPositiveConstraint.isValid at lines 41-57 interpolates the attacker-controlled value into errorMessage and calls context.buildConstraintViolationWithTemplate(errorMessage). Fix commit 4b38e7a3e20917e5c3329d0d4e9590bed9d578ab adds MessageSanitizer.escape(value), escaping backslash, braces, and dollar signs."
      }
    ],
    "exploit_precondition": "An attacker can supply a field value or message fragment containing EL syntax that is copied into a Bean Validation message template and then rendered by an EL-capable interpolation layer.",
    "guideline_id": "gl_mech_0040",
    "mechanism_id": "mech_bean_validation_message_el_interpolation_injection",
    "mechanism_name": "Bean Validation message template EL interpolation injection",
    "missing_guard": "The vulnerable flows do not escape expression-language metacharacters before the message reaches buildConstraintViolationWithTemplate, and they do not use message-parameter APIs, static templates, or a non-EL interpolator on the same path.",
    "rationale": "TraeX judge correctly flagged cron-utils as not sharing the Bean Validation sink. The remaining Dropwizard and BrowserUp evidence supports a tighter reusable buildConstraintViolationWithTemplate/message-template interpolation boundary.",
    "recall_follow_up": "After a sidecar change, rerun same-identity recall on the three representative Bean Validation/message-template cases. If misses persist, inspect whether candidate slicing includes buildConstraintViolationWithTemplate and sanitizer/fix symbols before broadening the query.",
    "representative_cases": [
      "dropwizard__dropwizard::CVE-2020-11002",
      "dropwizard__dropwizard::CVE-2020-5245",
      "browserup__browserup-proxy::CVE-2020-26282"
    ],
    "reviewer_notes": "This boundary is message-template syntax injection through Bean Validation, not general template execution and not generic parser exception handling. It should be kept separate from direct FreeMarker/Velocity template-source execution, SpEL evaluation-context selection, Jinjava sandbox bypass, and parser error-message cases whose downstream interpolation sink has not been source-reviewed.",
    "safe_fix_semantics": "Escape `{`, `}`, `$`, backslash, and `${` sequences before constructing the template, use message-parameter APIs or static templates that separate data from message syntax, or configure a non-EL message interpolator. The safe fix must occur before buildConstraintViolationWithTemplate or the equivalent interpolation sink.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "Dropwizard's ViolationCollector.addViolation calls context.buildConstraintViolationWithTemplate(msg). BrowserUp's LongPositiveConstraint.isValid calls context.buildConstraintViolationWithTemplate(errorMessage) after inserting the raw attacker-controlled value. In an EL-capable interpolator, the message template can interpret attacker-supplied expressions.",
    "source_shape": "The reviewed examples take attacker-controlled validation values or custom messages and include that text in a Bean Validation message template. Dropwizard passes msg into a constraint violation template, and BrowserUp formats an invalid numeric value into errorMessage before constructing the violation template."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.