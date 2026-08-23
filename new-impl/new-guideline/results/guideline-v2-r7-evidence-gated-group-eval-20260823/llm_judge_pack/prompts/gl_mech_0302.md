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
          "end_line": 2457,
          "file": "cbor/src/main/java/com/fasterxml/jackson/dataformat/cbor/CBORParser.java",
          "span_kind": "hunk",
          "start_line": 2425,
          "symbol": ""
        },
        {
          "end_line": 1718,
          "file": "cbor/src/main/java/com/fasterxml/jackson/dataformat/cbor/CBORParser.java",
          "span_kind": "hunk",
          "start_line": 1706,
          "symbol": ""
        },
        {
          "end_line": 3210,
          "file": "cbor/src/main/java/com/fasterxml/jackson/dataformat/cbor/CBORParser.java",
          "span_kind": "hunk",
          "start_line": 3204,
          "symbol": ""
        },
        {
          "end_line": 3231,
          "file": "cbor/src/main/java/com/fasterxml/jackson/dataformat/cbor/CBORParser.java",
          "span_kind": "hunk",
          "start_line": 3225,
          "symbol": ""
        },
        {
          "end_line": 3356,
          "file": "cbor/src/main/java/com/fasterxml/jackson/dataformat/cbor/CBORParser.java",
          "span_kind": "hunk",
          "start_line": 3351,
          "symbol": ""
        }
      ],
      "case_id": "case::9b9b0d36cb770b159aa5",
      "cve_ids": [
        "CVE-2020-28491"
      ],
      "cwe_ids": [
        "CWE-400",
        "CWE-770"
      ],
      "identity_key": "fasterxml__jackson-dataformats-binary::CVE-2020-28491",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 425,
          "file": "src/main/java/org/xerial/snappy/SnappyInputStream.java",
          "span_kind": "hunk",
          "start_line": 417,
          "symbol": ""
        },
        {
          "end_line": 31,
          "file": "src/test/java/org/xerial/snappy/SnappyTest.java",
          "span_kind": "hunk",
          "start_line": 26,
          "symbol": ""
        },
        {
          "end_line": 390,
          "file": "src/test/java/org/xerial/snappy/SnappyTest.java",
          "span_kind": "hunk",
          "start_line": 386,
          "symbol": ""
        },
        {
          "end_line": 343,
          "file": "src/test/java/org/xerial/snappy/SnappyTest.java",
          "span_kind": "hunk",
          "start_line": 330,
          "symbol": ""
        }
      ],
      "case_id": "case::48e7b535963df5deeae1",
      "cve_ids": [
        "CVE-2023-34455"
      ],
      "cwe_ids": [
        "CWE-770"
      ],
      "identity_key": "xerial__snappy-java::CVE-2023-34455",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster contains 19 CVEs primarily in parsing, decompression, and memory management code. Common mistakes include trusting untrusted size fields for allocation without validation, integer overflow in size arithmetic, and various logical errors such as missing type validation, unbounded recursion, and incorrect buffer offset handling. These vulnerabilities can lead to denial of service, out-of-bounds reads/writes, or memory exhaustion.",
  "guideline_group_key": "cluster_0056__mech_binary_length_unbounded_resource_use",
  "guideline_id": "gl_mech_0302",
  "guideline_text": "Trace attacker-controlled binary length fields, size counters, frame lengths, offsets, back-references, or decompressed-size metadata into memory allocation, buffer growth, parsing loops, frame handling, decompression, or resource-consuming work. Report code paths where protocol-specific upper bounds, arithmetic overflow checks, structural consistency checks, or expansion limits are absent before allocation or work expansion. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 12 historical CVE example(s), not as a project-specific signature. A safe implementation should enforce explicit size limits, validate arithmetic and offsets before use, reject malformed or oversized records early, and bound decompression or frame-processing work.",
  "mechanism": {
    "family": "resource_exhaustion_or_bounds",
    "mechanism_id": "mech_binary_length_unbounded_resource_use",
    "name": "unbounded binary length or size field drives resource use"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "CWE-770",
    "cwe_purity": 0.6667,
    "flags": [
      "mixed_cwe"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "unspecified",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 12
  }
}