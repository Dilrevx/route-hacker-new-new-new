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
    "exploit_precondition": "Needs a case where an attacker can configure or submit a callback/webhook destination that the application later invokes from the server side.",
    "guideline_id": "gl_mech_0007",
    "mechanism_id": "mech_ssrf_webhook_or_callback_fetch",
    "mechanism_name": "webhook or callback URL SSRF",
    "missing_guard": "The packet does not contain a representative webhook/callback source-to-sink path or corresponding missing destination guard. It should stay out of the released recall sidecar until representative source evidence exists.",
    "rationale": "The old guideline name over-framed this one-case group around webhook/callback semantics. The checked evidence supports direct URL download fetch instead, so the webhook/callback mechanism needs representative cases before promotion.",
    "recall_follow_up": "Do not evaluate feiyuchuixue__sz-boot-parent::CVE-2026-3189 as a positive for webhook/callback SSRF. If a future source-reviewed callback/webhook case appears, create a separate recall-consumed guideline and run same-identity recall for that boundary.",
    "representative_cases": [],
    "safe_fix_semantics": "Needs source-reviewed fix evidence showing destination validation, allowlisting, network-range blocking, or redirect-hop validation applied to the callback/webhook client before dispatch.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "A webhook/callback boundary would require evidence of server-initiated callback or notification delivery to a user-selected endpoint. That sink shape is not present in the checked CommonServiceImpl.urlDownload evidence.",
    "source_shape": "The current reviewed case is a direct file download URL, not a webhook dispatch, callback invocation, or stored integration endpoint callback flow."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.