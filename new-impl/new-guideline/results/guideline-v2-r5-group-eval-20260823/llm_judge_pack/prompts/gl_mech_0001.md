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
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities resulting from insecure defaults in XML processing. The majority involve XML parsers that do not disable DTD processing or external entity resolution, enabling XXE attacks. Other issues include insecure deserialization via XMLDecoder, XSLT extension function abuse, resource exhaustion from missing EOF checks, variable interpolation leaking system properties, and NTLM credential exposure through namespace URI resolution.",
  "guideline_group_key": "cluster_0000__mech_deserialization_untrusted_type_graph",
  "guideline_id": "gl_mech_0001",
  "guideline_text": "Trace untrusted serialized bytes, object streams, pickles, marshaled payloads, or type metadata into deserializers that instantiate classes, reconstruct object graphs, or invoke callbacks during object creation. Report code paths where allowed classes, object types, and construction side effects are not constrained before deserialization. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should use type allowlists, safe codecs, signature checks, or data-only formats instead of general object deserialization.",
  "mechanism": {
    "family": "deserialization",
    "mechanism_id": "mech_deserialization_untrusted_type_graph",
    "name": "untrusted deserialization with attacker-controlled type graph"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "small_group"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "information_disclosure",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 6
  }
}