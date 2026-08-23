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
    "boundary_text": "Unsafe XML parser external-resource resolution: externally supplied XML, SOAP, XML report, XML metadata, or XML configuration bytes reach DOM/SAX/StAX/JAXB/SOAP parser or XML transformation utilities that can process DOCTYPE, external general entities, external parameter entities, external DTDs, schemas, stylesheets, or equivalent external resources before a rejecting resolver or restrictive parser/factory feature is applied.",
    "evidence_refs": [
      {
        "identity_key": "allure-framework__allure2::CVE-2025-52888",
        "source_evidence": "Vulnerable checkout eaa87ff7d93e79074f7a1d785740bd3fed2f89fd: JunitXmlPlugin.parseRootElement lines 131-138 and XunitXmlPlugin.parseAssemblies lines 93-99 call DocumentBuilderFactory.newInstance(), newDocumentBuilder(), then builder.parse(parsedFile.toFile()) for XML result files without setting an entity resolver or parser feature that blocks external entities. Fix commit cbcb33719851ff70adce85d38e15d20fc58d4eb7 adds ClasspathEntityResolver and calls builder.setEntityResolver(...) in both parser paths."
      },
      {
        "identity_key": "apache__cxf-fediz::CVE-2018-8038",
        "source_evidence": "Vulnerable checkout 84b4d31adc6feaa1d2659f87edd1a2b5a88e9fef: DOMUtils creates a static DocumentBuilderFactory at line 68, sets FEATURE_SECURE_PROCESSING at line 72, but lacks disallow-doctype-decl in the static configuration. DOMUtils.readXml methods at lines 428-448 call DBF.newDocumentBuilder() and parse InputStream, Reader, or StreamSource inputs. Fix commit b6ed9865d0614332fa419fe4b6d0fe81bc2e660d adds DBF.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)."
      },
      {
        "identity_key": "aws_amplify__aws_sdk_android::CVE-2022-4725",
        "source_evidence": "Vulnerable checkout cfcce4079f005598b2a56b8a5c9a1eba1bf84710: XpathUtils.java line 48 creates static DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance(); lines 58-64 call factory.newDocumentBuilder().parse(is), and lines 88-90 open a URL stream before parsing. RegionMetadataParser.java lines 112-116 creates DocumentBuilderFactory.newInstance(), newDocumentBuilder(), then documentBuilder.parse(input). Fix commit c3e6d69422e1f0c80fe53f2d757b8df97619af2b adds disallow-doctype-decl, setXIncludeAware(false), and setExpandEntityReferences(false) in both parser utilities."
      },
      {
        "identity_key": "bonitasoft__bonita-connector-webservice::CVE-2020-36640",
        "source_evidence": "Vulnerable checkout 17a214d5a3f8af55080855a67a476497e3235689: SecureWSConnector.java around old line 392 creates DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument() for SOAP/XML response document creation, and around old line 452 creates TransformerFactory.newInstance().newTransformer() for XML/SOAP transformation without restrictive external access attributes. Fix commit a12ad691c05af19e9061d7949b6b828ce48815d5 imports XMLConstants and sets ACCESS_EXTERNAL_DTD=\"\", ACCESS_EXTERNAL_SCHEMA=\"\", and ACCESS_EXTERNAL_STYLESHEET=\"\"."
      }
    ],
    "exploit_precondition": "An attacker can cause the application to parse or transform XML containing a DOCTYPE, external entity, external DTD, schema, stylesheet, or equivalent external reference, and the XML processor runs in an environment where resolving that reference has file, network, credential, or disclosure impact.",
    "guideline_id": "gl_mech_0022",
    "mechanism_id": "mech_xml_external_entity_resolution",
    "mechanism_name": "unsafe XML parser external entity or DTD resolution",
    "missing_guard": "The vulnerable side constructs or reuses parser/transformer factories or builders without disabling DOCTYPE declarations and external general/parameter entity resolution on the exact XML processor instance, without setting restrictive XMLConstants external-access properties where applicable, and without installing a rejecting or tightly scoped EntityResolver before parse.",
    "rationale": "Allure, Fediz, AWS Amplify Android, and Bonita provide source-backed old/fix evidence for the same reusable mechanism: XML parser or transformer construction/reuse without a complete external-resource, DOCTYPE, or external-access guard before processing attacker-influenced XML. This row deliberately excludes XML expression injection, XMLDecoder deserialization, and EMF namespace URI external-location loading because they use different sinks and fixes.",
    "recall_follow_up": "If this boundary changes recall-consumed guideline text, run same-identity P3C64 recall on the representative cases and then the frozen full-143 identity list at Top-100, Top-150, and Top-200. Also inspect whether XPath expression injection, XMLDecoder, namespace URI loading, and third-party XML dependency cases move out of this XXE boundary instead of treating them as missed positives.",
    "representative_cases": [
      "allure-framework__allure2::CVE-2025-52888",
      "apache__cxf-fediz::CVE-2018-8038",
      "aws_amplify__aws_sdk_android::CVE-2022-4725",
      "bonitasoft__bonita-connector-webservice::CVE-2020-36640"
    ],
    "safe_fix_semantics": "Configure every XML parser, transformer, schema, or builder factory before processing untrusted XML: reject DOCTYPE where feasible, disable external general and parameter entities and external DTD loading, set restrictive external-access properties for schema/stylesheet/transformer flows, disable XInclude and entity expansion when applicable, and install a resolver that denies or strictly allowlists external resource resolution.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The input is parsed or transformed through DocumentBuilderFactory/DocumentBuilder, TransformerFactory/Transformer, or an equivalent XML processing utility. When external entity, DOCTYPE, schema, stylesheet, or external access processing remains enabled, XML processing can resolve attacker-selected external resources and expose local files, network endpoints, credentials, or sensitive parser-side effects.",
    "source_shape": "Application-controlled or externally supplied XML-like input is read from a test result file, stream, reader, URL-opened metadata stream, SOAP/configuration document, or equivalent XML carrier and passed to a Java XML parser or transformation utility."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.