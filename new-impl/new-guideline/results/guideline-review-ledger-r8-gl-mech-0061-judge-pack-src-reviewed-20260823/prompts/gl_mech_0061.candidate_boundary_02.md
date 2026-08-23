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
    "boundary_text": "Unsafe URI scheme open redirect: attacker-controlled redirect input reaches a browser navigation sink because the application checks only part of the URL or fails to reject non-browser-safe schemes such as javascript:, data:, or protocol-relative forms after final parsing.",
    "evidence_refs": [],
    "exploit_precondition": "Needs a representative case where an attacker can supply a redirect target using an unsafe or ambiguous scheme and have that exact parsed destination emitted to a browser navigation sink.",
    "guideline_id": "gl_mech_0061",
    "mechanism_id": "mech_open_redirect_unsafe_uri_scheme_only",
    "mechanism_name": "open redirect through unsafe URI scheme validation bypass",
    "missing_guard": "The checked packet does not prove that unsafe scheme filtering, rather than missing same-origin or context-path validation, is the key absent guard for the representative old-side cases.",
    "rationale": "The old guideline name over-focused on URI schemes. The checked evidence supports a broader final-destination policy boundary, while scheme-only bypass remains a narrower candidate needing its own source-backed representatives.",
    "recall_follow_up": "Do not evaluate the broader open-redirect representative cases as positives for this unsafe-scheme-only boundary. If a source-reviewed unsafe-scheme bypass case is found, keep it as a separate recall-consumed guideline and run same-identity recall for that boundary.",
    "representative_cases": [],
    "safe_fix_semantics": "Needs source-reviewed fix evidence that rejects non-browser-safe schemes or protocol-relative forms on the final parsed destination before the redirect/navigation sink.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "A promotable unsafe-scheme-only boundary would need an old-side source-to-sink trace showing the malicious scheme or protocol-relative form reaching a redirect/navigation sink because scheme validation was absent or applied to the wrong parsed value.",
    "source_shape": "The current packet shows a broader final-destination policy issue across login redirects and request-parameter redirects. It does not isolate a representative old-side case where unsafe URI scheme handling is the primary bypass mechanism."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.