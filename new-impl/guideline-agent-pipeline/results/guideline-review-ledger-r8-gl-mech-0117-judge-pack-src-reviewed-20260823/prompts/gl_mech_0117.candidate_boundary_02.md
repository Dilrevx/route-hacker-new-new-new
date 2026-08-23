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
    "boundary_text": "Webhook/callback SSRF: attacker-controlled webhook, callback, notification endpoint, or integration endpoint configuration is later invoked by the server without destination policy on the invoked endpoint.",
    "evidence_refs": [],
    "exploit_precondition": "Needs representative cases where an attacker configures or supplies a callback/webhook endpoint that the application later invokes from the server side.",
    "guideline_id": "gl_mech_0117",
    "mechanism_id": "mech_ssrf_webhook_or_callback_only",
    "mechanism_name": "attacker-controlled webhook or callback URL fetch",
    "missing_guard": "The checked evidence supports outbound destination policy gaps generally. It does not prove that callback/webhook dispatch semantics, rather than URL parsing/address-policy coverage, are the decisive shared missing guard.",
    "rationale": "The old group name over-scoped the evidence as webhook/callback fetching. The current source-reviewed evidence supports a broader server-side outbound destination-policy boundary, while webhook/callback-only remains a candidate needing its own representatives.",
    "recall_follow_up": "Do not evaluate the general SSRF destination-policy representatives as positives for a webhook/callback-only guideline. If a future source-reviewed webhook/callback dispatch case appears, keep it as a separate recall-consumed guideline and run same-identity recall for that boundary.",
    "representative_cases": [],
    "safe_fix_semantics": "Needs source-reviewed fix evidence showing destination validation, allowlisting, private-range blocking, parser-consistent checks, and redirect-hop validation applied to the webhook/callback client before dispatch.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "A promotable webhook/callback-only boundary would need source-to-sink evidence that a stored or submitted webhook/callback endpoint is actually dispatched by the server-side client without effective destination validation.",
    "source_shape": "The checked packet includes one webhook URL validator case and one general HTTP address-policy case, but it does not provide enough source-reviewed representatives to claim that webhook/callback dispatch is the shared released boundary for the whole group."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.