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
          "end_line": 50,
          "file": "authlib/jose/__init__.py",
          "span_kind": "phase21_022_review_entry_window",
          "start_line": 32,
          "symbol": "authlib.jose default jwt"
        },
        {
          "end_line": 42,
          "file": "authlib/jose/__init__.py",
          "span_kind": "file_region",
          "start_line": 40,
          "symbol": "authlib.jose default jwt.center_window_3"
        },
        {
          "end_line": 43,
          "file": "authlib/jose/__init__.py",
          "span_kind": "file_region",
          "start_line": 39,
          "symbol": "authlib.jose default jwt.center_window_5"
        },
        {
          "end_line": 44,
          "file": "authlib/jose/__init__.py",
          "span_kind": "file_region",
          "start_line": 38,
          "symbol": "authlib.jose default jwt.center_window_7"
        },
        {
          "end_line": 46,
          "file": "authlib/jose/__init__.py",
          "span_kind": "file_region",
          "start_line": 36,
          "symbol": "authlib.jose default jwt.center_window_11"
        }
      ],
      "case_id": "case::16b033f5dc501f76ab56",
      "cve_ids": [
        "CVE-2026-28802"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "authlib__authlib::CVE-2026-28802",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21.022 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 339,
          "file": "dsf-common/dsf-common-jetty/src/main/java/dev/dsf/common/config/AbstractJettyConfig.java",
          "span_kind": "phase21_022_review_entry_window",
          "start_line": 317,
          "symbol": "AbstractJettyConfig.configureSecurityHandler"
        }
      ],
      "case_id": "case::51013c17ccbf9d3cdd40",
      "cve_ids": [
        "CVE-2026-40939"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "datasharingframework__dsf::CVE-2026-40939",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21.022 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 627,
          "file": "src/flask_httpauth.py",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 620,
          "symbol": ""
        },
        {
          "end_line": 624,
          "file": "src/flask_httpauth.py",
          "span_kind": "file_region",
          "start_line": 622,
          "symbol": "src/flask_httpauth.py:620-627.center_window_3"
        },
        {
          "end_line": 625,
          "file": "src/flask_httpauth.py",
          "span_kind": "file_region",
          "start_line": 621,
          "symbol": "src/flask_httpauth.py:620-627.center_window_5"
        },
        {
          "end_line": 626,
          "file": "src/flask_httpauth.py",
          "span_kind": "file_region",
          "start_line": 620,
          "symbol": "src/flask_httpauth.py:620-627.center_window_7"
        },
        {
          "end_line": 628,
          "file": "src/flask_httpauth.py",
          "span_kind": "file_region",
          "start_line": 618,
          "symbol": "src/flask_httpauth.py:620-627.center_window_11"
        }
      ],
      "case_id": "case::d554d500e4a613626036",
      "cve_ids": [
        "CVE-2026-34531"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "miguelgrinberg__flask-httpauth::CVE-2026-34531",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 29,
          "file": "backend/app/auth/utils.py",
          "span_kind": "phase21_032_review_entry_window",
          "start_line": 17,
          "symbol": "AuthHandler JWT secret fallback"
        },
        {
          "end_line": 35,
          "file": "backend/app/auth/services/totp.py",
          "span_kind": "phase21_032_review_entry_window",
          "start_line": 26,
          "symbol": "TOTP Fernet key derived from JWT fallback"
        }
      ],
      "case_id": "case::1ef31cc78ef8df8dffdd",
      "cve_ids": [
        "CVE-2026-42869"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "socfortress__copilot::CVE-2026-42869",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21.032 materialized this label only after selecting a cached CVE intake backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster contains vulnerabilities that allow attackers to bypass authentication or authorization by exploiting missing validation checks, timing side-channels, insecure cryptographic operations, and session management flaws. The issues include failure to verify user existence, token validity, claim correctness, and the use of non-constant-time comparisons, weak PRNGs, and untrusted algorithm handling.",
  "guideline_group_key": "cluster_0089__pending_mech_cluster_89_authentication_bypass_and_token_validation_flaws",
  "guideline_id": "gl_mech_0509",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 8 historical CVE example(s), not as a project-specific signature. A safe implementation should add the required guard and bind it to the exact sensitive effect.",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_89_authentication_bypass_and_token_validation_flaws",
    "name": "Authentication bypass and token validation flaws"
  },
  "structural_sanity": {
    "assigned_case_count": 4,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "pending_review"
    ],
    "metadata_cve_count": 4,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 8
  }
}