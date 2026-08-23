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
    "boundary_decision": "needs_more_evidence",
    "boundary_label": "candidate_boundary_02b_parser_error_message_needs_evidence",
    "boundary_text": "Parser error message downstream EL risk: attacker-controlled parser input is copied into an exception or error message containing expression-language payload syntax, and that message may later be consumed by a validation, logging, UI, or message interpolation layer. This should not be promoted until the downstream interpolation/rendering sink is source-reviewed for the representative case.",
    "evidence_refs": [
      {
        "identity_key": "jmrozanec__cron-utils::CVE-2021-41269",
        "source_evidence": "Vulnerable CronParser.parse included the raw cron expression in IllegalArgumentException(String.format(\"Failed to parse '%s'. %s\", expression, e.getMessage()), e). Fix commit cfd2880f80e62ea74b92fa83474c2aabdb9899da removes the raw expression from the error message and tests `${...}` Runtime.exec-style payloads."
      },
      {
        "identity_key": "traex_judge_gl_mech_0040_initial",
        "source_evidence": "The first gl_mech_0040 ledger judge run split this case away from Bean Validation because the supplied evidence did not show buildConstraintViolationWithTemplate or an equivalent EL interpolation sink."
      }
    ],
    "exploit_precondition": "An attacker can supply a cron expression containing EL payload syntax that reaches CronParser.parse. A promotable boundary also needs evidence that the resulting error message is rendered or interpolated in an EL-capable context in a vulnerable deployment.",
    "guideline_id": "gl_mech_0040",
    "mechanism_id": "mech_parser_error_message_downstream_el_risk",
    "mechanism_name": "parser error message carrying attacker expression text into downstream interpolation risk",
    "missing_guard": "The exact missing guard is unresolved. It may be removing raw attacker input from parser error messages, escaping EL metacharacters before downstream rendering, or preventing those messages from reaching an EL-capable interpolator.",
    "rationale": "The patch proves raw attacker input was removed from an error message, but not that the same code path reaches an EL-capable interpolation sink. This is useful review evidence, not yet a promoted mechanism boundary.",
    "recall_follow_up": "Do not count cron-utils as a positive for the Bean Validation message-template boundary. If downstream interpolation evidence is collected, create a separate recall-consumed boundary and run same-identity recall for jmrozanec__cron-utils::CVE-2021-41269.",
    "representative_cases": [
      "jmrozanec__cron-utils::CVE-2021-41269"
    ],
    "reviewer_notes": "This row records the split suggested by advisory judge output. It keeps the source-reviewed CronParser patch evidence but prevents it from being used as support for the Bean Validation promoted boundary until the downstream sink is reviewed.",
    "safe_fix_semantics": "Current patch evidence supports removing raw attacker input from the parser error message. A complete promoted guideline would need source-reviewed evidence for the downstream sink and the corresponding escaping, static-template, or non-interpolating rendering fix.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "Potential sensitive effect is downstream interpretation of `${...}` expression text carried inside an exception or error message. The current evidence only shows exception-message construction and EL payload tests, not the later interpolating sink.",
    "source_shape": "The reviewed patch evidence shows CronParser.parse included the raw cron expression in an IllegalArgumentException message, and the fix removed the raw expression from the error message. This ledger has not confirmed a downstream buildConstraintViolationWithTemplate or equivalent EL interpolation sink for that exception message."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.