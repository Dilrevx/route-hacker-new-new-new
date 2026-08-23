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
    "boundary_label": "candidate_boundary_04_remaining_unreviewed_members",
    "boundary_text": "Remaining JWT signature or algorithm validation members should stay out of recall-consumed guideline text until source review confirms the exact token source, parser or validator sink, missing verification or algorithm/key guard, exploit precondition, and safe fix. They may include signature skipping, algorithm confusion, issuer/audience validation, key selection, or other authentication-token mechanisms, but those boundaries should be split after source evidence is collected.",
    "evidence_refs": [
      {
        "identity_key": "review_mech_0513_release_queue",
        "source_evidence": "mechanism-guideline-preview-v2-cluster-scope-r8-release-ready-20260823/review_queue.jsonl lists CVE-2023-48238, CVE-2026-28490, and CVE-2026-28498 as unsupported members of the pending JWT signature verification and algorithm handling group; no source-reviewed evidence is attached in this ledger."
      }
    ],
    "exploit_precondition": "Needs per-case review of how attacker-controlled token material reaches the validator and how accepted claims affect authentication or authorization decisions.",
    "guideline_id": "review_mech_0513",
    "mechanism_id": "pending_mech_jwt_signature_verification_unreviewed_members",
    "mechanism_name": "remaining JWT signature or algorithm validation members needing source review",
    "missing_guard": "Potential missing guards include signed-JWS parsing, non-none algorithm policy, trusted key selection, issuer/audience/claim enforcement, or algorithm allowlists. The exact guard must be proven per case.",
    "rationale": "The group-level JWT label is plausible but too broad for publication or retrieval without source evidence. Keeping the remainder as needs_more_evidence prevents bad-case or label pressure from becoming hardcoded guideline routing.",
    "recall_follow_up": "Do not use these unreviewed members as positives for same-identity recall claims until their source-reviewed boundary is filled and judged. If their sidecar text changes later, run a separate recall A/B.",
    "representative_cases": [
      "unknown_source_member::CVE-2023-48238",
      "unknown_source_member::CVE-2026-28490",
      "unknown_source_member::CVE-2026-28498"
    ],
    "reviewer_notes": "This row preserves the umbrella group's unreviewed remainder without using it as evidence for the three promoted boundaries. Future work should review these members and either assign them to one of the promoted submechanisms or create additional source-backed token-validation boundaries.",
    "safe_fix_semantics": "Needs per-case patch/source review. Likely fixes may include signature-verifying parser APIs, explicit algorithm allowlists, trusted key configuration, or stricter claim validation, but those fixes should not be inferred from the umbrella label alone.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "Potential sinks include JWT/JWS parsers, OIDC token validators, algorithm dispatch, key selection, claim validators, or authentication principal construction. The exact sink for each remaining member is not source-reviewed here.",
    "source_shape": "The r8 review queue lists these as historical members of the pending JWT signature verification and algorithm handling group, but this ledger has not inspected their old-side source spans or patches."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.