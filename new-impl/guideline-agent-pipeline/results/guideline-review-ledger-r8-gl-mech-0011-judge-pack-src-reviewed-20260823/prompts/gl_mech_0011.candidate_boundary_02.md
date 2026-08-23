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
    "boundary_text": "Archive extraction denial of service: malformed archive metadata, cyclic links, null entries, or unbounded extraction recursion/loops cause the extraction process to hang, recurse indefinitely, crash, or exhaust resources.",
    "evidence_refs": [],
    "exploit_precondition": "Needs a representative case where an attacker can submit an archive with crafted metadata that reaches the vulnerable extraction loop or parser on the server side.",
    "guideline_id": "gl_mech_0011",
    "mechanism_id": "mech_archive_extraction_cycle_or_null_dos",
    "mechanism_name": "archive extraction denial of service from cyclic links, null handling, or unbounded extraction loops",
    "missing_guard": "The packet does not show the exact absent bound, visited-set, null check, cycle check, or metadata validation needed for this mechanism. It should remain out of the released recall sidecar until such source evidence exists.",
    "rationale": "The cluster summary is overbroad for DoS. Without concrete source evidence, this candidate boundary is a review queue item rather than a semantic guideline ready for recall.",
    "recall_follow_up": "Do not evaluate the archive-entry traversal representative cases as positives for this DoS boundary. If a source-reviewed cycle/null/unbounded-loop archive case is found, create a separate recall-consumed guideline and run same-identity recall for that boundary.",
    "representative_cases": [],
    "safe_fix_semantics": "Needs source-reviewed fix evidence showing cycle detection, null-safe metadata handling, bounded recursion/iteration, archive entry limits, or equivalent resource controls applied before or inside the vulnerable extraction loop.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "A promotable DoS boundary would need evidence of a server-side extraction loop, recursion, parser, or metadata traversal that can be made non-terminating or resource-exhausting by attacker-controlled archive contents. That evidence is not present in the checked packet.",
    "source_shape": "The current r8 packet mentions infinite-loop/null-cycle failures in the cluster summary but does not provide a representative source-to-sink trace showing the malformed archive metadata source, the loop/null/cycle-sensitive extraction operation, and the missing termination or validation guard."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.