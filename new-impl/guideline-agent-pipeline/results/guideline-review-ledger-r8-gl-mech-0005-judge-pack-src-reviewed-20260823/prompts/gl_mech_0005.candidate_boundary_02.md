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
    "boundary_label": "candidate_boundary_02",
    "boundary_text": "Path traversal candidate cases that have only review-entry provenance, partial source traces, or ambiguous existing validation should remain in the review queue until the exact source, sink, missing containment guard, exploit precondition, and safe fix are checked.",
    "evidence_refs": [],
    "exploit_precondition": "Needs per-case evidence of attacker control over the path material and a filesystem/resource effect that crosses an authorization or containment boundary.",
    "guideline_id": "gl_mech_0005",
    "mechanism_id": "mech_path_traversal_review_entry_or_partial_evidence",
    "mechanism_name": "path traversal candidates with review-entry-only or partial guard evidence",
    "missing_guard": "Needs proof that normalized or canonical containment is absent, ineffective, or applied to the wrong value on the vulnerable old-side path. For Graylog-like cases, the review must establish whether ensureFileWithinBundleDir is missing, bypassable, or not used on each sensitive path.",
    "rationale": "The r8 worklist and judge notes explicitly warn that most gl_mech_0005 examples provide only patch-derived review windows, and that the group has mixed-label/possible outlier concerns. This row preserves those cases as review work rather than inflating the promoted boundary.",
    "recall_follow_up": "Do not evaluate review-entry-only or partial-guard cases as positives for the promoted normalized-containment boundary until source evidence assigns them to that boundary. If later source review confirms them, add representative cases and rerun same-identity recall after sidecar changes.",
    "representative_cases": [],
    "safe_fix_semantics": "Needs source-reviewed patch evidence showing canonical containment, component-safe prefix checks, path allowlisting, basename extraction, or another fix tied to the vulnerable sink.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "Needs per-case confirmation that attacker-controlled path material reaches a filesystem or resource sink outside the intended base. Review windows alone, or evidence of a sink with an existing validation helper, do not establish a missing or bypassable guard.",
    "source_shape": "The current worklist includes review-entry-only examples such as Zrlog, JClouds, sz-boot-parent, GeoWebCache, Venice, and others, plus Graylog evidence where a filename reaches download/delete operations but the packet also says downloadBundle validates the supplied filename before resolving under bundleDir. These examples are insufficient to promote a shared missing-containment boundary without more source detail."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.