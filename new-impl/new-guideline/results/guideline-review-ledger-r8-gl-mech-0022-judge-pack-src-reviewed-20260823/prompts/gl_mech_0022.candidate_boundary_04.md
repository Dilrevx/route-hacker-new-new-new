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
    "boundary_decision": "split_further",
    "boundary_label": "candidate_boundary_04",
    "boundary_text": "XML namespace/package URI external-location loading: XML model/resource loading accepts package namespace URIs or schema/location hints as resolvable locations, allowing an untrusted model file to trigger loading of an unregistered local or remote URI even when ordinary DTD and external-entity parser features are disabled.",
    "evidence_refs": [
      {
        "identity_key": "archimatetool__archi::CVE-2023-40235",
        "source_evidence": "Vulnerable checkout ad679a46454209b318e3d9479d0e37707ccb5fd7: ArchimateResourceFactory.createResource lines 98-104 already sets disallow-doctype-decl=true, load-external-dtd=false, external-general-entities=false, and external-parameter-entities=false. Fix commit bcab676beddfbeddffecacf755b6692f0b0151f1 adds XMLResource.OPTION_USE_PACKAGE_NS_URI_AS_LOCATION=false with the comment 'Don't allow loading an unregistered URI in case of exploits.' This supports a distinct XML namespace/package URI location-loading boundary, not the same classic XXE parser boundary."
      }
    ],
    "exploit_precondition": "An attacker can supply an Archi/EMF XML model that includes namespace/package URI metadata pointing at a sensitive or attacker-observable location, and the application loads it through the affected resource factory.",
    "guideline_id": "gl_mech_0022",
    "mechanism_id": "mech_xml_namespace_location_loading",
    "mechanism_name": "XML namespace/package URI external location loading",
    "missing_guard": "The vulnerable-side ArchimateResourceFactory already disables DOCTYPE, external DTD loading, external general entities, and external parameter entities, but it does not set XMLResource.OPTION_USE_PACKAGE_NS_URI_AS_LOCATION to false.",
    "rationale": "The source evidence shows a different XML resource-loading mechanism: DTD/entity parser features are already disabled, and the security fix disables namespace/package URI-as-location resolution. Treating this as ordinary XXE would blur the source, sink, and safe-fix semantics.",
    "recall_follow_up": "Do not count Archi as a positive for the classic XXE boundary. If this split boundary becomes release-ready, create a separate retrieval guideline and run same-identity recall for Archi plus any future source-reviewed namespace/location cases.",
    "representative_cases": [
      "archimatetool__archi::CVE-2023-40235"
    ],
    "safe_fix_semantics": "Keep the existing XML parser feature hardening and additionally set XMLResource.OPTION_USE_PACKAGE_NS_URI_AS_LOCATION to false before resource loading so namespace/package URIs are not treated as resolvable locations.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The EMF XMLResource load path may resolve a namespace/package URI as an external location, causing information disclosure or external resource access through model loading rather than through classic DOCTYPE/entity expansion.",
    "source_shape": "An untrusted XML/EMF model resource contains namespace or package URI metadata that the framework may interpret as a location during resource loading."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.