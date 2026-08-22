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
          "end_line": 73,
          "file": "src/main/java/com/rabbitmq/client/impl/SocketFrameHandler.java",
          "span_kind": "hunk",
          "start_line": 52,
          "symbol": ""
        },
        {
          "end_line": 4,
          "file": "src/main/java/com/rabbitmq/client/impl/nio/SslEngineFrameBuilder.java",
          "span_kind": "hunk",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 187,
          "file": "src/main/java/com/rabbitmq/client/impl/SocketFrameHandler.java",
          "span_kind": "hunk",
          "start_line": 181,
          "symbol": ""
        },
        {
          "end_line": 4,
          "file": "src/main/java/com/rabbitmq/client/impl/Frame.java",
          "span_kind": "hunk",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 65,
          "file": "src/test/java/com/rabbitmq/client/test/FrameBuilderTest.java",
          "span_kind": "hunk",
          "start_line": 59,
          "symbol": ""
        }
      ],
      "case_id": "case::c3fce8d0b7accb6c3e4b",
      "cve_ids": [
        "CVE-2023-46120"
      ],
      "cwe_ids": [
        "CWE-400"
      ],
      "identity_key": "rabbitmq__rabbitmq-java-client::CVE-2023-46120",
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
  "cluster_summary": "This cluster comprises vulnerabilities where size or length fields from untrusted binary input are used to allocate memory or control operations without adequate validation. Common flaws include missing upper bounds, integer overflow in arithmetic, invalid back-reference offsets, and improper handling of edge cases, leading to memory exhaustion, data leaks, or denial of service.",
  "guideline_group_key": "cluster_0021__mech_toctou_mutable_object_reuse",
  "guideline_id": "gl_mech_0118",
  "guideline_text": "Trace mutable files, paths, objects, identities, request fields, or shared state that are checked before use into sensitive file, state, permission, memory, or resource effects that depend on the earlier check. Report code paths where the checked value is not stabilized with a handle, lock, transaction, immutable copy, or atomic operation before the effect. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 8 historical CVE example(s), not as a project-specific signature. A safe implementation should bind the check to a stable reference or perform the check and effect under the same atomic operation or synchronization boundary.",
  "mechanism": {
    "family": "race_or_lifecycle",
    "mechanism_id": "mech_toctou_mutable_object_reuse",
    "name": "time-of-check to time-of-use on mutable object"
  },
  "structural_sanity": {
    "assigned_case_count": 3,
    "cwe_majority": "CWE-400",
    "cwe_purity": 0.5,
    "flags": [
      "mixed_cwe"
    ],
    "metadata_cve_count": 3,
    "primary_hcvr_majority": "unspecified",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 8
  }
}