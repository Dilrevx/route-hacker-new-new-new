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
    "boundary_decision": "split_further",
    "boundary_label": "candidate_boundary_04",
    "boundary_text": "Redirect-following SSRF: an application validates or approves an initial URL, then an HTTP client follows one or more server-controlled redirects to a different scheme, host, port, or resolved address without reapplying the same destination policy before the next request.",
    "evidence_refs": [],
    "exploit_precondition": "An attacker can control either the initial URL or a redirect target served by the initial URL, and can cause the client to follow the redirect inside a protected network context.",
    "guideline_id": "gl_mech_0116",
    "mechanism_id": "mech_ssrf_redirect_following_client",
    "mechanism_name": "SSRF through redirect-following client",
    "missing_guard": "The missing guard is per-hop validation: final redirected scheme, host, port, DNS-resolved address, and allowlist/private-address policy are not checked before following the redirect.",
    "rationale": "The original guideline text is coherent as a vulnerability mechanism, but the reviewed gl_mech_0116 examples mostly establish direct URL/proxy SSRF, renderer external-resource SSRF, or credential/trust-boundary confusion. The current source evidence does not establish redirect following as the shared boundary for this group.",
    "recall_follow_up": "Keep redirect-following SSRF as a separate candidate mechanism. Do not count bigsk1, cbioportal, DHIS2, FastGPT, or mcp-atlassian as source-reviewed redirect positives unless source evidence shows an initial allowed URL followed by an unsafe redirected destination.",
    "representative_cases": [],
    "safe_fix_semantics": "Disable automatic redirects or revalidate every redirect hop against the same destination policy before issuing the next request.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "A later redirected request reaches a destination that would have been rejected by the policy applied to the original URL.",
    "source_shape": "An outbound HTTP request is made after an initial destination decision, and the HTTP client may automatically follow redirect responses."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.