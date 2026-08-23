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
    "boundary_label": "candidate_boundary_02",
    "boundary_text": "Renderer external-resource SSRF: attacker-controlled document, SVG, image, template, diagram, or similar rich-content input is handed to a renderer, converter, transcoder, or macro processor that resolves external URLs or resource references during rendering, without an explicit external-resource policy enforced on that renderer instance.",
    "evidence_refs": [
      {
        "identity_key": "dhis2__dhis2-core::CVE-2022-41949",
        "source_evidence": "Committed r5/r8 source evidence records that the /svg.png endpoint accepts caller-controlled SVG markup as a form parameter, forwards it to convertToPng, sanitizes SVG text, then calls Batik PNGTranscoder.transcode without disabling external resources. The fix adds SVGAbstractTranscoder.KEY_ALLOW_EXTERNAL_RESOURCES=false before transcode."
      },
      {
        "identity_key": "xwiki-contrib__macro-plantuml::CVE-2026-42140",
        "source_evidence": "Committed r5 group evidence records PlantUMLMacro.computeServer returning the macro server parameter or global PlantUML server URL without parsing or trusted-domain validation, and executeSync passing computeServer(parameters) into plantUMLRenderer.renderDiagram. The patch parses the URL and checks URLSecurityManager.isDomainTrusted inside computeServer before the render-service handoff."
      }
    ],
    "exploit_precondition": "An attacker can submit content or parameters consumed by the rendering path, and the rendering engine or configured render service can initiate network requests from the server environment.",
    "guideline_id": "gl_mech_0116",
    "mechanism_id": "mech_renderer_external_resource_ssrf",
    "mechanism_name": "renderer or document converter external-resource SSRF",
    "missing_guard": "The vulnerable path does not disable external resource resolution or validate the render service destination before the renderer is invoked. The missing guard is renderer-specific: for Batik, external resource loading is enabled; for render-service handoff, the chosen server URL is not checked against a trusted-domain policy before rendering.",
    "rationale": "DHIS2 and XWiki/PlantUML are SSRF-like, but the source and sink are renderer/resource-resolution paths, not ordinary proxy or webhook clients and not redirect-following HTTP clients. They should be kept as a separate mechanism boundary.",
    "recall_follow_up": "Do not evaluate this boundary with direct-proxy SSRF cases only. If released, run same-identity recall for renderer/resource-resolution cases separately and inspect whether the guideline retrieves renderer call sites rather than generic HTTP clients.",
    "representative_cases": [
      "dhis2__dhis2-core::CVE-2022-41949",
      "xwiki-contrib__macro-plantuml::CVE-2026-42140"
    ],
    "safe_fix_semantics": "Set renderer/converter options that deny external resources by default, or parse and validate the render service URL against trusted domains before invoking the renderer. The guard must be applied to the exact renderer or service call that resolves resources.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The content reaches Batik PNGTranscoder.transcode, PlantUML renderDiagram, or an equivalent renderer/converter capable of resolving external resources or contacting a configured render service. The sensitive effect is a server-side request made during rendering rather than a direct application HTTP proxy call.",
    "source_shape": "An authenticated or otherwise authorized user supplies rich content or a render-server parameter, such as SVG markup or a PlantUML server URL, that is later consumed by a server-side renderer or conversion service."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.