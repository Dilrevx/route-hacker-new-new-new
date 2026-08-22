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
          "end_line": 1057,
          "file": "core/src/main/java/org/bitcoinj/script/ScriptExecution.java",
          "span_kind": "phase21_022_review_entry_window",
          "start_line": 1019,
          "symbol": "ScriptExecution.correctlySpends"
        }
      ],
      "case_id": "case::36bec90e0bb9b9a4e2f8",
      "cve_ids": [
        "CVE-2026-44714"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "bitcoinj__bitcoinj::CVE-2026-44714",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21.022 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 53,
          "file": "src/dsa-2.0.js",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 47,
          "symbol": ""
        },
        {
          "end_line": 125,
          "file": "src/dsa-2.0.js",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 120,
          "symbol": ""
        },
        {
          "end_line": 51,
          "file": "src/dsa-2.0.js",
          "span_kind": "file_region",
          "start_line": 49,
          "symbol": "src/dsa-2.0.js:47-53.center_window_3"
        },
        {
          "end_line": 52,
          "file": "src/dsa-2.0.js",
          "span_kind": "file_region",
          "start_line": 48,
          "symbol": "src/dsa-2.0.js:47-53.center_window_5"
        },
        {
          "end_line": 55,
          "file": "src/dsa-2.0.js",
          "span_kind": "file_region",
          "start_line": 45,
          "symbol": "src/dsa-2.0.js:47-53.center_window_11"
        }
      ],
      "case_id": "case::d1b601697cea815d481e",
      "cve_ids": [
        "CVE-2026-4600"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "kjur__jsrsasign::CVE-2026-4600",
      "primary_hcvr_type": "authentication_session_token_validation",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster contains 40 CVEs covering various cryptographic implementation errors, including missing input validation (buffer offsets, shift amounts), timing side-channel vulnerabilities, use of insecure algorithms/modes (ECB, SHA-1), missing parameter validation (DH public key, DSA parameters, point-on-curve), certificate/trust anchor validation issues, signature encoding malleability, arithmetic errors (carry propagation, integer overflow), infinite loops in modular arithmetic, flawed verification logic, missing error handling, lossy byte-to-string conversion, caching logic flaws, and SSH protocol sequence number mishandling. Each vulnerability arises from a specific coding mistake that weakens the security guarantee of cryptographic operations.",
  "guideline_group_key": "cluster_0046__pending_mech_cluster_46_missing_validation_of_cryptographic_parameters_and_keys",
  "guideline_id": "gl_mech_0265",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 7 historical CVE example(s), not as a project-specific signature. A safe implementation should Add input validation checks: verify public key range and subgroup, use appropriate parameter sizes, perform point-on-curve validation, ensure correct number of Miller-Rabin iterations based on actual bitlength, retry on invalid signature components, verify public key hash against output script..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_46_missing_validation_of_cryptographic_parameters_and_keys",
    "name": "Missing validation of cryptographic parameters and keys"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authentication_session_token_validation",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 7
  }
}