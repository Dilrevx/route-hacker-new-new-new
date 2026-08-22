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

Guideline group payload:
{
  "case_examples": [
    {
      "anchor_examples": [
        {
          "end_line": 19,
          "file": "ohmo/gateway/router.py",
          "span_kind": "phase21_027_review_entry_window",
          "start_line": 8,
          "symbol": "session_key_for_message"
        }
      ],
      "case_id": "case::678983ade1700827c35d",
      "cve_ids": [
        "CVE-2026-6729"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "hkuds__openharness::CVE-2026-6729",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21.027 materialized this label only after selecting a cached CVE intake backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 40,
          "file": "src/main/java/de/presti/ree6/commands/impl/mod/Import.java",
          "span_kind": "phase21_026_review_entry_window",
          "start_line": 25,
          "symbol": "Import.onPerform"
        },
        {
          "end_line": 75,
          "file": "src/main/java/de/presti/ree6/commands/impl/mod/EmbedSender.java",
          "span_kind": "phase21_026_review_entry_window",
          "start_line": 27,
          "symbol": "EmbedSender.onPerform"
        },
        {
          "end_line": 57,
          "file": "src/main/java/de/presti/ree6/commands/impl/community/TwitchNotifier.java",
          "span_kind": "phase21_026_review_entry_window",
          "start_line": 47,
          "symbol": "TwitchNotifier.onPerform"
        },
        {
          "end_line": 57,
          "file": "src/main/java/de/presti/ree6/commands/impl/community/InstagramNotifier.java",
          "span_kind": "phase21_026_review_entry_window",
          "start_line": 47,
          "symbol": "InstagramNotifier.onPerform"
        },
        {
          "end_line": 57,
          "file": "src/main/java/de/presti/ree6/commands/impl/community/RedditNotifier.java",
          "span_kind": "phase21_026_review_entry_window",
          "start_line": 47,
          "symbol": "RedditNotifier.onPerform"
        }
      ],
      "case_id": "case::0b2b6793b545a144f160",
      "cve_ids": [
        "CVE-2022-39302"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "ree6_applications__ree6::CVE-2022-39302",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "Phase 21.026 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster covers authorization vulnerabilities where the application fails to properly validate sender identity, trust boundaries, or access policies. The majority of issues stem from using mutable or partial identifiers for authorization, treating empty allowlists as permissive, missing authorization gates on secondary event types, or incorrectly merging authorization contexts. The cluster also includes a few distinct sub-patterns such as pre-authentication crypto work and stale queued action validation.",
  "guideline_group_key": "cluster_0080__mech_object_owner_scope_missing_authz",
  "guideline_id": "gl_mech_0363",
  "guideline_text": "Trace attacker-selected resource identifiers, object IDs, tenant IDs, or administrative action targets into sensitive read, write, mutation, deletion, workflow, or administrative operations on the selected resource. Report code paths where the authorization decision is not bound to both the current principal and the exact resource or tenant being affected. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 22 historical CVE example(s), not as a project-specific signature. A safe implementation should check ownership or tenant scope before the effect and carry that checked identity into the data access or mutation.",
  "mechanism": {
    "family": "authorization",
    "mechanism_id": "mech_object_owner_scope_missing_authz",
    "name": "missing object-owner or tenant-scope authorization"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 22
  }
}