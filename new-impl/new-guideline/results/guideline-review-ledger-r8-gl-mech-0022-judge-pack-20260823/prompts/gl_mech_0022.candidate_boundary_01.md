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
    "Do not invent new source evidence. If evidence is insufficient, return needs_evidence."
  ],
  "task": "Review one source-reviewed guideline boundary ledger row."
}

Ledger boundary payload:
{
  "judge_mode": "source_reviewed_boundary_advisory",
  "ledger_row": {
    "boundary_decision": "promote_boundary",
    "boundary_label": "candidate_boundary_01",
    "boundary_text": "Unsafe XML parser external-resource resolution: externally supplied XML, SOAP, XML report, or XML configuration bytes reach DOM/SAX/StAX/JAXB/SOAP parser instances that can process DOCTYPE, external general entities, external parameter entities, external DTDs, schemas, stylesheets, or equivalent external resources before a rejecting resolver or restrictive parser feature is applied.",
    "evidence_refs": [
      {
        "identity_key": "allure-framework__allure2::CVE-2025-52888",
        "source_evidence": "Vulnerable checkout eaa87ff7d93e79074f7a1d785740bd3fed2f89fd: JunitXmlPlugin.parseRootElement lines 131-138 and XunitXmlPlugin.parseAssemblies lines 93-99 call DocumentBuilderFactory.newInstance(), newDocumentBuilder(), then builder.parse(parsedFile.toFile()) for XML result files without setting an entity resolver or parser feature that blocks external entities. Fix commit cbcb33719851ff70adce85d38e15d20fc58d4eb7 adds ClasspathEntityResolver and calls builder.setEntityResolver(...) in both parser paths."
      },
      {
        "identity_key": "apache__cxf-fediz::CVE-2018-8038",
        "source_evidence": "Vulnerable checkout 84b4d31adc6feaa1d2659f87edd1a2b5a88e9fef: DOMUtils creates a static DocumentBuilderFactory at line 68, sets FEATURE_SECURE_PROCESSING at line 72, but lacks disallow-doctype-decl in the static configuration. DOMUtils.readXml methods at lines 428-448 call DBF.newDocumentBuilder() and parse InputStream, Reader, or StreamSource inputs. Fix commit b6ed9865d0614332fa419fe4b6d0fe81bc2e660d adds DBF.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)."
      }
    ],
    "exploit_precondition": "An attacker can cause the application to parse XML containing a DOCTYPE, external entity, external DTD, schema, stylesheet, or equivalent external reference, and the parser runs in an environment where resolving that reference has file, network, credential, or disclosure impact.",
    "guideline_id": "gl_mech_0022",
    "mechanism_id": "mech_xml_external_entity_resolution",
    "mechanism_name": "unsafe XML parser external entity or DTD resolution",
    "missing_guard": "The vulnerable side constructs or reuses parser factories/builders without disabling DOCTYPE declarations and external general/parameter entity resolution on the exact parser instance, and without installing a rejecting or tightly scoped EntityResolver before parse.",
    "rationale": "Allure and Fediz provide source-backed old/fix evidence for the same reusable mechanism: XML parser construction or reuse without a complete external-resource/DOCTYPE guard before parsing attacker-controlled XML. This row deliberately excludes XML expression injection, XMLDecoder deserialization, and EMF namespace URI external-location loading because they use different sinks and fixes.",
    "recall_follow_up": "If this boundary changes recall-consumed guideline text, run same-identity P3C64 recall on the representative cases and then the frozen full-143 identity list at Top-100, Top-150, and Top-200. Also inspect whether XPath, XSLT, XMLDecoder, namespace URI loading, and third-party XML dependency cases move out of this XXE boundary instead of treating them as missed positives.",
    "representative_cases": [
      "allure-framework__allure2::CVE-2025-52888",
      "apache__cxf-fediz::CVE-2018-8038"
    ],
    "safe_fix_semantics": "Configure every parser factory or builder before parsing untrusted XML: reject DOCTYPE where feasible, disable external general and parameter entities and external DTD loading, set restrictive external-access properties for schema/stylesheet flows, and install a resolver that denies or strictly allowlists external resource resolution.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The input is parsed through DocumentBuilderFactory/DocumentBuilder or an equivalent XML parser utility. When external entity or DOCTYPE processing remains enabled, parsing can resolve attacker-selected external resources and expose local files, network endpoints, or sensitive parser-side effects.",
    "source_shape": "Application-controlled or externally supplied XML-like input is read from a test result file, stream, reader, SOAP/configuration document, or equivalent XML carrier and passed to a Java XML parser utility."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only.