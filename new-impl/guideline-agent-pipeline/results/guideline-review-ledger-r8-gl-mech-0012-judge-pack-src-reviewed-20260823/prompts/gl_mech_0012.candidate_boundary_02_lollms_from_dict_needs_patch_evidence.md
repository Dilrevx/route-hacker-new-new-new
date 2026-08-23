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
    "boundary_label": "candidate_boundary_02_lollms_from_dict_needs_patch_evidence",
    "boundary_text": "Message deserialization stored-XSS risk: attacker-controlled message `content` is loaded from serialized data through a `from_dict`-style deserializer and later returned to browser-facing message views or export/rendering paths without sanitization or HTML encoding. This should remain unpromoted until the source patch or reviewed old/new hunk confirms the deserializer or downstream renderer was actually fixed for this CVE.",
    "evidence_refs": [
      {
        "identity_key": "parisneo__lollms::CVE-2026-1116",
        "source_evidence": "GitHub advisory GHSA-w676-j9x4-3hq2 states that CVE-2026-1116 is XSS in the `from_dict` method of `AppLollmsMessage` due to lack of sanitization or HTML encoding of the `content` field when deserializing user-provided data, and references commit 9767b882dbc893c388a286856beeaead69b8292a."
      },
      {
        "identity_key": "parisneo__lollms::CVE-2026-1116",
        "source_evidence": "Raw file checks for `backend/message.py` at commit 9767b882dbc893c388a286856beeaead69b8292a and its parent both show `AppLollmsMessage.from_dict` returning `content=data.get(\"content\", \"\")`; the fetched commit API diff for 9767b882 lists changes to social routes, direct-message routes, and a migration script, not a `backend/message.py` hunk."
      },
      {
        "identity_key": "parisneo__lollms::CVE-2026-1116",
        "source_evidence": "`backend/routers/discussion/message.py` returns `target_message.content` in MessageOutput and can export message content through HTML-generating paths, which is consistent with a browser-rendering risk, but this is not enough to prove the CVE-specific fixed deserialization path without a matching patch hunk."
      }
    ],
    "exploit_precondition": "An attacker can supply serialized message data consumed by `AppLollmsMessage.from_dict`, and another user later views or exports that message through a browser-rendered path. The actual exploit path and fixed code location still need source review.",
    "guideline_id": "gl_mech_0012",
    "mechanism_id": "mech_message_from_dict_missing_html_sanitization",
    "mechanism_name": "message deserialization missing HTML sanitization before browser rendering",
    "missing_guard": "The suspected missing guard is sanitizer or HTML-output encoding for the deserialized `content` field before it becomes browser-visible. The exact repaired guard is unresolved because the referenced patch evidence primarily modifies social and direct-message routes, not the `AppLollmsMessage.from_dict` path described by the advisory.",
    "rationale": "The advisory describes a plausible same-family stored-XSS mechanism, but the fetched referenced patch does not prove the described `from_dict` repair. The correct action is to preserve it as a review item rather than silently merge it into the social-route sanitizer boundary.",
    "recall_follow_up": "Do not count CVE-2026-1116 as a positive for the promoted social-route sanitizer boundary unless its materialized slices overlap the same source/sink/fix. If a later patch proves the `from_dict` path, create a separate recall-consumed boundary and rerun same-identity recall on that fixed identity set.",
    "representative_cases": [
      "parisneo__lollms::CVE-2026-1116"
    ],
    "reviewer_notes": "Keep this row as evidence-preserving `needs_more_evidence`. It should not block the promoted CVE-2026-1115 stored-social-content boundary, but it should prevent CVE-2026-1116 from being counted as fully source-reviewed until the exact old/new source delta is found or a different authoritative fix is identified.",
    "safe_fix_semantics": "A promotable fix would sanitize or encode `content` at deserialization, storage, or final rendering, and would include regression coverage for malicious HTML/JavaScript payloads in `AppLollmsMessage.from_dict`. The current source evidence is insufficient to assert this exact fix.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The potential effect is stored or deserialized message content later returned by discussion/message APIs and rendered or exported as HTML. `backend/routers/discussion/message.py` returns `target_message.content` and exports message content through markdown/HTML conversion paths, but this ledger has not confirmed the exact vulnerable source-to-render sink chain for CVE-2026-1116.",
    "source_shape": "GitHub advisory GHSA-w676-j9x4-3hq2 describes `AppLollmsMessage.from_dict` in `backend/message.py` as assigning `content=data.get(\"content\", \"\")` from user-provided serialized data. The current public patch commit referenced by the advisory did not show a modification to `backend/message.py` in the fetched diff, and raw old/new file checks still showed the same `content=data.get(\"content\", \"\")` assignment."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.