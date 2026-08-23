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
    "boundary_label": "candidate_boundary_01_lollms_social_content_stored_xss",
    "boundary_text": "Stored social-content XSS through missing HTML sanitization: a social, discussion, direct-message, comment, group-name, or rich-text endpoint accepts attacker-controlled content and stores or returns it for later browser rendering without applying an allowlist-based HTML sanitizer or equivalent output encoding on the same content field. Report code paths where stored user content reaches ORM/database objects or message responses before sanitization, and later browser-facing views can render that content as HTML or script.",
    "evidence_refs": [
      {
        "identity_key": "parisneo__lollms::CVE-2026-1115",
        "source_evidence": "GitHub advisory GHSA-8wrq-fv5f-pfp2 describes stored XSS in the LoLLMs social feature before 2.2.0, specifically `create_post` in `backend/routers/social/__init__.py`, where user-provided content was directly assigned to `DBPost` without sanitization and later executed in users' browsers."
      },
      {
        "identity_key": "parisneo__lollms::CVE-2026-1115",
        "source_evidence": "Patch 9767b882dbc893c388a286856beeaead69b8292a imports `bleach`, defines `sanitize_content`, and changes `create_post` from `content=post_data.content` to sanitized `clean_content`; it also sanitizes `update_post` content and `add_comment_to_post` content before DB assignment."
      },
      {
        "identity_key": "parisneo__lollms::CVE-2026-1115",
        "source_evidence": "The same patch changes `backend/routers/social/dm.py` to define the same `sanitize_content`, sanitize broadcast direct-message content before creating DBDirectMessage rows, sanitize group conversation names before DBConversation creation, and sanitize `send_direct_message` content before storing it. It also adds `scripts/sanitize_existing_content.py` to sanitize existing posts, comments, direct messages, and conversation names."
      }
    ],
    "exploit_precondition": "An authenticated user can submit social posts, comments, direct messages, broadcast message content, or group names containing HTML/JavaScript payloads, and another user or administrator later views the stored content in the web UI or export/rendering path that interprets it as HTML.",
    "guideline_id": "gl_mech_0012",
    "mechanism_id": "mech_stored_social_content_missing_html_sanitization",
    "mechanism_name": "stored social content missing HTML sanitization before persistence or rendering",
    "missing_guard": "The vulnerable routes lacked an allowlist sanitizer or output-encoding guard on the same user-controlled content fields before storage/return. There was no `bleach.clean`-style restriction of tags and attributes for posts, comments, DMs, broadcast DMs, or group names before creating or updating database records.",
    "rationale": "The advisory and patch directly show attacker-controlled stored social content reaching database/message sinks before sanitization, with the fix introducing allowlist sanitization before persistence.",
    "recall_follow_up": "This source-only boundary has no assigned frozen-143 case metadata in the r8 worklist. If the sidecar text changes, run same-identity recall only on a fixed identity set containing parisneo__lollms::CVE-2026-1115 and materialized slices for `backend/routers/social/__init__.py`, `backend/routers/social/dm.py`, `DBPost`, `DBComment`, `DBDirectMessage`, `DBConversation`, and `sanitize_content`.",
    "representative_cases": [
      "parisneo__lollms::CVE-2026-1115"
    ],
    "reviewer_notes": "This is missing HTML sanitization/output encoding for stored social content. It is narrower than a sanitizer-policy bypass: the reviewed patch introduces an active sanitizer where none existed, rather than repairing a subtle allowlist bypass in an existing sanitizer. Keep CSV formula injection and response-header XSS outside this boundary unless their source/sink/fix evidence is separately reviewed.",
    "safe_fix_semantics": "Define a restrictive sanitizer policy, apply it before storing or updating each social content field, and migrate existing stored content through the same sanitizer. The observed fix adds `sanitize_content` backed by `bleach.clean(..., tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)` and applies it to create/update post, add comment, broadcast DM, direct-message send, group conversation name, and existing database content cleanup paths.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The persisted social content is later displayed to other users in browser-facing feeds, comment views, direct messages, or conversation views. Unsanitized HTML or JavaScript can execute in the victim's browser under the application origin, enabling account takeover, session theft, or wormable stored XSS behavior.",
    "source_shape": "LoLLMs social and direct-message routes accept request-controlled post, update, comment, direct-message, broadcast, and group-name content from FastAPI/Pydantic request models and handler parameters. The vulnerable code assigned fields such as `post_data.content`, `comment_data.content`, `content`, and `payload.name` directly into DBPost, DBComment, DBDirectMessage, or DBConversation objects."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.