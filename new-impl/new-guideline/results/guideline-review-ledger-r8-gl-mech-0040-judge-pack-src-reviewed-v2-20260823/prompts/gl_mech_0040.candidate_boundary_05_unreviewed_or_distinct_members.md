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
    "boundary_label": "candidate_boundary_05_unreviewed_or_distinct_members",
    "boundary_text": "The remaining historical members of the old gl_mech_0040 umbrella should not be promoted as one recall-consumed guideline until each has source-level evidence for source shape, evaluator sink, missing guard, exploit precondition, and fix semantics. They may include FreeMarker, AviatorScript, general EL, or other expression-evaluator mechanisms, but their exact boundaries need source review before release.",
    "evidence_refs": [
      {
        "identity_key": "gl_mech_0040_release_json",
        "source_evidence": "mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/guidelines/gl_mech_0040.json lists the remaining members and sub-pattern names, but this ledger has not inspected their vulnerable source, sink, missing guard, exploit precondition, or fix semantics."
      }
    ],
    "exploit_precondition": "Needs per-case review of how attacker input reaches the evaluator and whether the server-side execution context makes the evaluator reachable under realistic conditions.",
    "guideline_id": "gl_mech_0040",
    "mechanism_id": "mech_template_expression_untrusted_eval",
    "mechanism_name": "untrusted template or expression evaluation",
    "missing_guard": "Potential missing guards include safe class resolvers, non-EL interpolators, restricted feature sets, escaping, allowlists, or evaluator sandboxing. The exact guard must be proven per case before these members are used to define recall-consumed text.",
    "rationale": "The broad r8 guideline is plausible but mixes multiple evaluator technologies and fix strategies. Without per-case source evidence, these members should remain in the review queue rather than strengthening or weakening recall claims.",
    "recall_follow_up": "Do not count these unreviewed members as semantic support for any promoted boundary. Collect source evidence first, then rerun same-identity recall only after the sidecar text is updated from reviewed evidence.",
    "representative_cases": [
      "unknown_source_member::CVE-2010-5327",
      "unknown_source_member::CVE-2021-21244",
      "unknown_source_member::CVE-2023-29213",
      "unknown_source_member::CVE-2023-51387",
      "unknown_source_member::CVE-2023-51388",
      "unknown_source_member::CVE-2024-41667",
      "unknown_source_member::CVE-2025-35036"
    ],
    "reviewer_notes": "This row deliberately prevents the old broad template-expression umbrella from being treated as fully source-reviewed. The reviewed sub-boundaries above can be judged and later promoted independently; remaining members need source review or should become separate mechanism rows.",
    "safe_fix_semantics": "Needs per-case patch/source review. Likely fixes may include restricted class resolvers, safe interpolators, feature-set allowlists, escaping, or sandboxed evaluator contexts, but the proper fix family should not be inferred from the broad umbrella alone.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "Potential sinks include template engines, Bean Validation interpolators, AviatorScript evaluators, and general expression evaluators, but the exact source-to-sink path and sensitive effect for each listed member is not yet confirmed by reviewed source evidence in this ledger.",
    "source_shape": "The r8 guideline JSON lists these CVEs under sub-patterns such as FreeMarker unrestricted class resolution, unsafe default EL evaluation in Bean Validation messages, AviatorScript feature set too permissive, and general EL injection. This row has not source-reviewed their old-side source spans."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.