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
    "boundary_decision": "promote_boundary",
    "boundary_label": "candidate_boundary_02_missing_media_token_filter_rejection",
    "boundary_text": "Missing-token media filter bypass: a servlet or web filter protects media, file, cover, thumbnail, or document-download endpoints but continues the filter chain when the expected request token is absent or empty. Report code paths where downstream controllers expose protected content after the filter only attempts validation when a token exists, instead of rejecting unauthenticated requests before chain.doFilter.",
    "evidence_refs": [
      {
        "identity_key": "booklore-app__booklore::CVE-2025-62614",
        "source_evidence": "Patch commit b226c43343cd0cef4c1cd54bc3dcdef90b147133 has subject `Secured /media endpoints behind authentication tokens`. It changes CoverJwtFilter.doFilterInternal so token == null || token.isEmpty() sends SC_UNAUTHORIZED `Missing authentication token` and returns before chain.doFilter."
      },
      {
        "identity_key": "booklore-app__booklore::CVE-2025-62614",
        "source_evidence": "The GitHub advisory GHSA-363g-fhcq-hvqp says the CoverJwtFilter continued request processing even when no authentication token was provided, allowing unauthenticated access to /api/v1/media endpoints and bypassing intended canDownload permissions."
      }
    ],
    "exploit_precondition": "An unauthenticated remote user can call protected media endpoints without a token parameter and the downstream controller exposes the requested content.",
    "guideline_id": "review_mech_0514",
    "mechanism_id": "mech_media_filter_missing_token_allows_controller_access",
    "mechanism_name": "media endpoint filter lets unauthenticated requests continue when token is missing",
    "missing_guard": "The vulnerable filter only validates token when token != null and does not return an HTTP 401 for null or empty token before calling chain.doFilter.",
    "rationale": "The patch and advisory both identify the missing-token branch as the source of unauthenticated media access, with a direct fail-closed filter fix.",
    "recall_follow_up": "After a sidecar change, rerun same-identity recall for booklore-app__booklore::CVE-2025-62614. Inspect whether candidate windows include CoverJwtFilter.doFilterInternal, request.getParameter(\"token\"), response.sendError, and chain.doFilter.",
    "representative_cases": [
      "booklore-app__booklore::CVE-2025-62614"
    ],
    "reviewer_notes": "This boundary is about filter-chain fail-open behavior on missing authentication material for media endpoints. It should remain separate from token cryptographic verification and from per-resource canDownload authorization checks.",
    "safe_fix_semantics": "Reject null or empty token values with HTTP 401 before any authentication branch and before chain.doFilter, then keep rejecting invalid token or authentication exceptions. Controller annotations alone should not be the only guard for these endpoints.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "When the token is missing, the request proceeds through chain.doFilter to media controllers that serve covers, thumbnails, PDFs, CBX pages, or other book content without an authenticated security context.",
    "source_shape": "A Java Spring servlet filter for media endpoints reads a token request parameter before invoking local JWT or OIDC authentication helpers."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.