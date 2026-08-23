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
    "boundary_label": "candidate_boundary_03_public_jwt_secret_fallback",
    "boundary_text": "Public default JWT secret fallback: authentication code signs, verifies, encrypts, decrypts, or derives security keys from an environment variable or configuration value but silently falls back to a hardcoded default secret that is published in examples or source code. Report code paths where deployments without an explicit secret keep using a known shared value for JWTs, session tokens, OAuth state, TOTP encryption, or related authentication artifacts.",
    "evidence_refs": [
      {
        "identity_key": "socfortress__copilot::CVE-2026-42869",
        "source_evidence": "Patch 4640511a0cf2e7b144a71375b5b349a8318cb186 is titled `fix(auth): remove hardcoded JWT secret fallback`. Its commit message states that JWT signing used a hardcoded fallback matching `.env.example`, so deployments without JWT_SECRET signed tokens with a publicly known value, and that a second copy lived in the TOTP service."
      },
      {
        "identity_key": "socfortress__copilot::CVE-2026-42869",
        "source_evidence": "The patch changes `.env.example` from `JWT_SECRET=bL4unrkoxtFs1MT6A7Ns2yMLkduyuqrkTxDV9CjlbNc=` to `JWT_SECRET=REPLACE_ME`, adds `_KNOWN_COMPROMISED_JWT_SECRET`, adds `_load_jwt_secret()` that raises if unset or compromised, changes `AuthHandler.secret = _load_jwt_secret()`, and changes TOTP fallback key derivation to use `AuthHandler.secret`."
      }
    ],
    "exploit_precondition": "A target deployment runs CoPilot with the default or missing JWT_SECRET value from the published example/source. An attacker knows the public fallback and can craft or analyze tokens or related auth artifacts accepted by the server.",
    "guideline_id": "review_mech_0509",
    "mechanism_id": "mech_public_default_jwt_secret_fallback",
    "mechanism_name": "public default JWT signing secret fallback",
    "missing_guard": "The vulnerable code does not fail closed when `JWT_SECRET` is unset and does not reject the known compromised default value. It also duplicates the fallback in the TOTP path instead of deriving from a single validated secret source.",
    "rationale": "The patch and commit message establish a precise mechanism: missing fail-closed secret loading leaves JWT/TOTP auth artifacts protected by a public default key.",
    "recall_follow_up": "After sidecar update, rerun same-identity recall for socfortress__copilot::CVE-2026-42869. Candidate slices should include `backend/app/auth/utils.py`, `_load_jwt_secret`, `JWT_SECRET`, the hardcoded fallback string, and `backend/app/auth/services/totp.py` fallback derivation.",
    "representative_cases": [
      "socfortress__copilot::CVE-2026-42869"
    ],
    "reviewer_notes": "This is a secret-management and auth-token signing boundary, not an artifact validation or endpoint-authz boundary. It should be searchable with terms such as default secret, hardcoded JWT secret, env fallback, fail fast, and known compromised value.",
    "safe_fix_semantics": "Load JWT_SECRET through a single helper that raises at startup if it is unset or equals the known compromised default, replace the example secret with `REPLACE_ME`, and make dependent services such as TOTP derive from the validated AuthHandler secret rather than carrying their own fallback.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The secret is used for JWT signing/verification and as the basis for fallback TOTP encryption. A deployment that leaves the variable unset uses a publicly known shared secret, enabling attackers who know the default to forge or decrypt authentication artifacts depending on the affected path.",
    "source_shape": "CoPilot's authentication utility defines `AuthHandler.secret` from `os.environ.get(\"JWT_SECRET\", \"bL4unrkoxtFs1MT6A7Ns2yMLkduyuqrkTxDV9CjlbNc=\")`, and the TOTP service derives a Fernet key from the same fallback when a dedicated TOTP key is absent."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.