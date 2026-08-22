You are judging a reusable security-audit guideline group.

Evaluate whether the guideline accurately describes a coherent vulnerability mechanism shared by the listed cases.
Do not evaluate embedding recall, rank, or whether known anchors were hit.
Do not require all cases to share the same CWE or dataset label; those labels are only weak context.
Prefer mechanism-level judgments: source shape, sink shape, missing guard, exploit precondition, and safe fix.

Return JSON only with this schema:
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

Guideline group payload:
{
  "case_examples": [
    {
      "anchor_examples": [
        {
          "end_line": 138,
          "file": "plugins/junit-xml-plugin/src/main/java/io/qameta/allure/junitxml/JunitXmlPlugin.java",
          "span_kind": "primary_junit_xxe_anchor",
          "start_line": 131,
          "symbol": "JunitXmlPlugin.parseRootElement"
        },
        {
          "end_line": 99,
          "file": "plugins/xunit-xml-plugin/src/main/java/io/qameta/allure/xunitxml/XunitXmlPlugin.java",
          "span_kind": "primary_xunit_xxe_anchor",
          "start_line": 93,
          "symbol": "XunitXmlPlugin.parseAssemblies"
        },
        {
          "end_line": 1,
          "file": "allure-plugin-api/src/main/java/io/qameta/allure/parser/ClasspathEntityResolver.java",
          "span_kind": "fix_bound_absent_guard_anchor",
          "start_line": 1,
          "symbol": "ClasspathEntityResolver absent in vulnerable checkout"
        }
      ],
      "case_id": "case::d3ad9d37ff642d737876",
      "cve_ids": [
        "CVE-2025-52888"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "allure-framework__allure2::CVE-2025-52888",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "readResults enumerates XML result files and parseRootElement creates a default DocumentBuilderFactory and DocumentBuilder, then parses parsedFile.toFile() directly. In the reviewed vulnerable checkout no EntityResolver or external-entity restriction is configured for JUnit XML input.",
        "The JUnit parser sink constructs a default XML parser and calls builder.parse(parsedFile.toFile()). This is the source-backed XXE sink fixed by adding ClasspathEntityResolver in commit cbcb337.",
        "readResults enumerates XUnit XML result files and parseAssemblies creates a default DocumentBuilderFactory and DocumentBuilder before parsing the file. In the vulnerable checkout no resolver blocks external entities."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 75,
          "file": "plugins/core/src/main/java/org/apache/cxf/fediz/core/util/DOMUtils.java",
          "span_kind": "hunk",
          "start_line": 62,
          "symbol": ""
        },
        {
          "end_line": 438,
          "file": "systests/idp/src/test/java/org/apache/cxf/fediz/systests/idp/IdpTest.java",
          "span_kind": "hunk",
          "start_line": 433,
          "symbol": ""
        }
      ],
      "case_id": "case::1797a28bb5466a283e38",
      "cve_ids": [
        "CVE-2018-8038"
      ],
      "cwe_ids": [
        "CWE-20"
      ],
      "identity_key": "apache__cxf-fediz::CVE-2018-8038",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 99,
          "file": "com.archimatetool.model/src/com/archimatetool/model/util/ArchimateResourceFactory.java",
          "span_kind": "hunk",
          "start_line": 94,
          "symbol": ""
        }
      ],
      "case_id": "case::88e6c956e089802f9f52",
      "cve_ids": [
        "CVE-2023-40235"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "archimatetool__archi::CVE-2023-40235",
      "primary_hcvr_type": "information_disclosure",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 51,
          "file": "aws-android-sdk-core/src/main/java/com/amazonaws/util/XpathUtils.java",
          "span_kind": "phase21_008_review_entry_window",
          "start_line": 45,
          "symbol": "XpathUtils.factory"
        },
        {
          "end_line": 117,
          "file": "aws-android-sdk-core/src/main/java/com/amazonaws/regions/RegionMetadataParser.java",
          "span_kind": "phase21_008_review_entry_window",
          "start_line": 109,
          "symbol": "RegionMetadataParser.internalParse"
        }
      ],
      "case_id": "case::cf239d51163faec634d0",
      "cve_ids": [
        "CVE-2022-4725"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "aws_amplify__aws_sdk_android::CVE-2022-4725",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.008 materialized this label only after taking a Phase 21.007 source-acquisition work order, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 219,
          "file": "src/main/java/org/bonitasoft/connectors/ws/SecureWSConnector.java",
          "span_kind": "hunk",
          "start_line": 205,
          "symbol": ""
        },
        {
          "end_line": 352,
          "file": "src/main/java/org/bonitasoft/connectors/ws/SecureWSConnector.java",
          "span_kind": "hunk",
          "start_line": 323,
          "symbol": ""
        },
        {
          "end_line": 34,
          "file": "src/main/java/org/bonitasoft/connectors/ws/SecureWSConnector.java",
          "span_kind": "hunk",
          "start_line": 29,
          "symbol": ""
        },
        {
          "end_line": 294,
          "file": "src/main/java/org/bonitasoft/connectors/ws/SecureWSConnector.java",
          "span_kind": "hunk",
          "start_line": 288,
          "symbol": ""
        },
        {
          "end_line": 276,
          "file": "src/main/java/org/bonitasoft/connectors/ws/SecureWSConnector.java",
          "span_kind": "hunk",
          "start_line": 268,
          "symbol": ""
        }
      ],
      "case_id": "case::9a7b844e8b28fd94c2cd",
      "cve_ids": [
        "CVE-2020-36640"
      ],
      "cwe_ids": [
        "CWE-611"
      ],
      "identity_key": "bonitasoft__bonita-connector-webservice::CVE-2020-36640",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 22,
          "file": "bundles/org.jkiss.utils/src/org/jkiss/utils/xml/XMLUtils.java",
          "span_kind": "hunk",
          "start_line": 17,
          "symbol": ""
        },
        {
          "end_line": 67,
          "file": "bundles/org.jkiss.utils/src/org/jkiss/utils/xml/XMLUtils.java",
          "span_kind": "hunk",
          "start_line": 62,
          "symbol": ""
        }
      ],
      "case_id": "case::45b82aa255ef0169c7a4",
      "cve_ids": [
        "CVE-2021-3836"
      ],
      "cwe_ids": [
        "CWE-611"
      ],
      "identity_key": "dbeaver__dbeaver::CVE-2021-3836",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 15,
          "file": "src/main/java/de/timroes/axmlrpc/ResponseParser.java",
          "span_kind": "hunk",
          "start_line": 10,
          "symbol": ""
        },
        {
          "end_line": 53,
          "file": "src/main/java/de/timroes/axmlrpc/ResponseParser.java",
          "span_kind": "hunk",
          "start_line": 45,
          "symbol": ""
        }
      ],
      "case_id": "case::cc5c03bacc98ad7d8216",
      "cve_ids": [
        "CVE-2020-36641"
      ],
      "cwe_ids": [
        "CWE-611"
      ],
      "identity_key": "gturri__axmlrpc::CVE-2020-36641",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 182,
          "file": "src/main/java/com/gargoylesoftware/htmlunit/javascript/host/xml/XSLTProcessor.java",
          "span_kind": "phase21_012_review_entry_window",
          "start_line": 121,
          "symbol": "XSLTProcessor.transform"
        }
      ],
      "case_id": "case::41ace2ccec11b6e8056e",
      "cve_ids": [
        "CVE-2023-26119"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "htmlunit__htmlunit::CVE-2023-26119",
      "primary_hcvr_type": "template_expression_injection",
      "trace_evidence": [
        "Phase 21.012 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities resulting from insecure defaults in XML processing. The majority involve XML parsers that do not disable DTD processing or external entity resolution, enabling XXE attacks. Other issues include insecure deserialization via XMLDecoder, XSLT extension function abuse, resource exhaustion from missing EOF checks, variable interpolation leaking system properties, and NTLM credential exposure through namespace URI resolution.",
  "guideline_group_key": "cluster_0000__mech_deserialization_untrusted_type_graph",
  "guideline_id": "gl_mech_0001",
  "guideline_text": "Trace untrusted serialized bytes, object streams, pickles, marshaled payloads, or type metadata into deserializers that instantiate classes, reconstruct object graphs, or invoke callbacks during object creation. Report code paths where allowed classes, object types, and construction side effects are not constrained before deserialization. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 68 historical CVE example(s), not as a project-specific signature. A safe implementation should use type allowlists, safe codecs, signature checks, or data-only formats instead of general object deserialization.",
  "mechanism": {
    "family": "deserialization",
    "mechanism_id": "mech_deserialization_untrusted_type_graph",
    "name": "untrusted deserialization with attacker-controlled type graph"
  },
  "structural_sanity": {
    "assigned_case_count": 12,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.5,
    "flags": [
      "mixed_hcvr",
      "mixed_cwe"
    ],
    "metadata_cve_count": 12,
    "primary_hcvr_majority": "unspecified",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 68
  }
}