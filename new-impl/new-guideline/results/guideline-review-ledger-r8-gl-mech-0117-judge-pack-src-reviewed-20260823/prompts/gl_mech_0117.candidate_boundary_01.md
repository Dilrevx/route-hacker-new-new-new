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
    "boundary_label": "candidate_boundary_01",
    "boundary_text": "Server-side outbound URL destination policy gap: attacker-influenced URL, endpoint, host, webhook, callback, plugin, bridge, or configuration input reaches server-side HTTP request construction or dispatch before the same request destination is parsed, normalized, resolved, and constrained under the effective network destination policy. The policy must bind the URL actually used by the outbound client, including scheme, host parsing, DNS/IP resolution, private/loopback/link-local/multicast/cloud-metadata ranges, redirect hops, and parser inconsistencies where applicable.",
    "evidence_refs": [
      {
        "identity_key": "bugsink__bugsink::CVE-2026-44502",
        "source_evidence": "The r8 case packet records alerts/service_backends/webhook_security.py validate_webhook_url: old validation uses urllib.parse.urlparse to decide scheme and hostname before outbound policy checks. The patch switches to requests preparation plus urllib3 parsing and rejects raw non-RFC characters, confirming a parser-boundary destination policy issue."
      },
      {
        "identity_key": "cc-tweaked__cc-tweaked::CVE-2023-37262",
        "source_evidence": "The r8 case packet records projects/core/src/main/java/dan200/computercraft/core/apis/http/options/AddressPredicate.java PrivatePattern.matches as the IP destination policy predicate used to deny private/internal addresses. The old code checks any-local, loopback, link-local, and site-local addresses; the patch adds cloud metadata addresses and multicast ranges, confirming incomplete destination policy coverage."
      }
    ],
    "exploit_precondition": "An attacker can submit, configure, or influence a URL or network endpoint that the server-side application later validates and uses for outbound network access, and the server has network reachability to destinations that should be blocked from attacker influence.",
    "guideline_id": "gl_mech_0117",
    "mechanism_id": "mech_ssrf_outbound_url_destination_policy_gap",
    "mechanism_name": "server-side outbound URL request with incomplete destination policy",
    "missing_guard": "The old-side evidence lacks complete effective-destination validation. Bugsink uses urllib.parse.urlparse to decide scheme and hostname before outbound policy checks, while the patch switches to requests preparation plus urllib3 parsing and rejects raw non-RFC characters, indicating a parser-boundary mismatch. CC-Tweaked's private-address predicate omitted cloud metadata and multicast destinations, so the deny policy did not cover all sensitive internal targets.",
    "rationale": "The source-reviewed evidence supports a reusable SSRF destination-policy mechanism for server-side outbound URL handling. The common mechanism is broader than webhook/callback dispatch: the reviewed cases share attacker-influenced outbound destinations and incomplete effective destination constraints.",
    "recall_follow_up": "If this boundary changes recall-consumed guideline text, rerun same-identity P3C64 recall first for bugsink__bugsink::CVE-2026-44502 and cc-tweaked__cc-tweaked::CVE-2023-37262, then rerun the frozen 143 identity set at Top-100, Top-150, and Top-200. Inspect query wording, candidate slicing around validators versus dispatch sites, redirect handling, and network-policy terminology without using known anchors, labels, or regex fallback in retrieval.",
    "representative_cases": [
      "bugsink__bugsink::CVE-2026-44502",
      "cc-tweaked__cc-tweaked::CVE-2023-37262"
    ],
    "safe_fix_semantics": "A safe implementation parses and canonicalizes the URL using the same semantics as the outbound HTTP client, rejects malformed or ambiguous raw inputs, enforces allowed schemes, resolves and checks the effective host/IP against private, loopback, link-local, multicast, unique-local, and cloud-metadata ranges, and reapplies equivalent checks after redirects or DNS changes before dispatch.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The sensitive effect is server-side network access to a destination selected or influenced by an attacker. Bugsink's webhook URL validation decides whether a configured webhook URL is accepted for outbound delivery; CC-Tweaked's AddressPredicate governs whether the server-side HTTP API may reach a requested address. If the policy misses parser edge cases or internal address ranges, the outbound client can reach disallowed destinations.",
    "source_shape": "The source-reviewed examples expose caller-influenced outbound destinations to server-side request logic: a webhook URL validation path where the URL parser decision controls whether a webhook destination can be used, and an HTTP API address predicate that decides whether a requested outbound address is blocked as private or internal."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.