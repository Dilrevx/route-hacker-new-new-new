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
    "boundary_label": "candidate_boundary_05_remaining_unreviewed_members",
    "boundary_text": "Remaining authentication and authorization validation-flow members should stay out of recall-consumed guideline text until source review confirms the exact request source, authentication or authorization decision point, missing guard, sensitive effect, exploit precondition, and safe fix. They may involve JWT refresh signature verification, unauthenticated login flows, arbitrary user-information retrieval, SSO/LDAP/OIDC configuration, or per-resource permission checks, but those mechanisms should be split after source evidence is collected.",
    "evidence_refs": [
      {
        "identity_key": "grassrootza__grassroot-platform::CVE-2021-29455",
        "source_evidence": "Patch commit a2e6e885f8183a066d938cf909fd813a7af7d67f removes JwtService.refreshToken and the /token/refresh endpoint. The CVE states JWT signatures were not properly verified when refreshing JWTs, so this member likely belongs near the JWT verification family but is not promoted here to avoid duplicating review_mech_0513 without a separate boundary."
      },
      {
        "identity_key": "metersphere__metersphere::CVE-2025-62604",
        "source_evidence": "The public advisory GHSA-vj5x-7374-rf96 states that a logic flaw allowed unauthenticated attackers to log in as any user and was patched in v2.10.25-lts. A broad v2.10.24-lts...v2.10.25-lts diff includes LoginController.login switching to loginLocal and UserLoginService authentication changes, but this ledger has not isolated a precise source/sink/guard/fix boundary."
      }
    ],
    "exploit_precondition": "Needs per-case review of how attacker-controlled authentication material or unauthenticated requests reach the decision point and how accepted identity or user data affects access.",
    "guideline_id": "review_mech_0514",
    "mechanism_id": "pending_mech_authentication_authorization_flow_unreviewed_members",
    "mechanism_name": "remaining authentication or authorization validation-flow members needing source review",
    "missing_guard": "Potential missing guards include signed-JWS validation during token refresh, explicit authentication before login/session creation, user-specific authorization checks, or secure SSO mode selection. The exact missing guard must be proven per case.",
    "rationale": "The remaining members are plausible authentication or authorization vulnerabilities, but the current evidence is insufficient for a paper-facing guideline boundary and should remain quarantined.",
    "recall_follow_up": "Do not use these remaining members as positives for same-identity recall claims until a source-reviewed boundary is filled and judged. If a future sidecar mentions them, run same-identity recall separately for the promoted boundary.",
    "representative_cases": [
      "grassrootza__grassroot-platform::CVE-2021-29455",
      "metersphere__metersphere::CVE-2025-62604"
    ],
    "reviewer_notes": "This holding row prevents the broad review_mech_0514 cluster from becoming a vague guideline. Future work should either assign Grassroot to a JWT-refresh verification boundary or create a separate endpoint-removal boundary, and should inspect MeterSphere with a narrower patch or source diff before promotion.",
    "safe_fix_semantics": "Needs per-case patch/source review. Likely fixes may include removing unsafe refresh endpoints, validating tokens before login/session creation, checking resource permissions, or restricting authentication mode dispatch, but these fixes should not be inferred from the broad cluster label alone.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "Potential sinks include JWT refresh endpoints, login controllers, user-information endpoints, session creation, or protected resource access. The exact sink for each remaining member needs focused source review.",
    "source_shape": "The r8 review queue lists these as members of a broad authentication/authorization validation-flow group, but this ledger has not promoted them because the reviewed patch evidence either overlaps a JWT verification mechanism already tracked elsewhere or is too broad for a precise boundary here."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.