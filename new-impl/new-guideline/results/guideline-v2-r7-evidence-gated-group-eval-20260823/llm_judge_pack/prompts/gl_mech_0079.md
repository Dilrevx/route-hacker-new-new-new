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
          "end_line": 40,
          "file": "server/src/main/java/org/apache/seata/server/cluster/raft/serializer/CustomDeserializer.java",
          "span_kind": "hunk",
          "start_line": 37,
          "symbol": ""
        },
        {
          "end_line": 113,
          "file": "server/src/main/java/org/apache/seata/server/cluster/raft/snapshot/RaftSnapshotSerializer.java",
          "span_kind": "hunk",
          "start_line": 111,
          "symbol": ""
        },
        {
          "end_line": 115,
          "file": "server/src/main/java/org/apache/seata/server/cluster/raft/snapshot/RaftSnapshotSerializer.java",
          "span_kind": "hunk",
          "start_line": 115,
          "symbol": ""
        },
        {
          "end_line": 85,
          "file": "server/src/main/java/org/apache/seata/server/cluster/raft/sync/RaftSyncMessageSerializer.java",
          "span_kind": "hunk",
          "start_line": 85,
          "symbol": ""
        },
        {
          "end_line": 111,
          "file": "server/src/main/java/org/apache/seata/server/cluster/raft/sync/RaftSyncMessageSerializer.java",
          "span_kind": "hunk",
          "start_line": 109,
          "symbol": ""
        }
      ],
      "case_id": "case::05f42f5713ee7d081131",
      "cve_ids": [
        "CVE-2025-32897"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "apache__incubator-seata::CVE-2025-32897",
      "primary_hcvr_type": "iris",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 67,
          "file": "src/main/java/emissary/core/IMobileAgent.java",
          "span_kind": "hunk",
          "start_line": 59,
          "symbol": ""
        },
        {
          "end_line": 237,
          "file": "src/main/java/emissary/util/PayloadUtil.java",
          "span_kind": "hunk",
          "start_line": 230,
          "symbol": ""
        },
        {
          "end_line": 13,
          "file": "src/main/java/emissary/util/PayloadUtil.java",
          "span_kind": "hunk",
          "start_line": 1,
          "symbol": ""
        },
        {
          "end_line": 238,
          "file": "src/main/java/emissary/pickup/WorkBundle.java",
          "span_kind": "hunk",
          "start_line": 231,
          "symbol": ""
        },
        {
          "end_line": 181,
          "file": "src/main/java/emissary/util/PayloadUtil.java",
          "span_kind": "hunk",
          "start_line": 109,
          "symbol": ""
        }
      ],
      "case_id": "case::95050a7be52981b4486d",
      "cve_ids": [
        "CVE-2021-32634"
      ],
      "cwe_ids": [
        "CWE-502"
      ],
      "identity_key": "nationalsecurityagency__emissary::CVE-2021-32634",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 490,
          "file": "math/src/main/java/com/powsybl/math/matrix/SparseMatrix.java",
          "span_kind": "primary_powsybl_sparsematrix_unfiltered_deserialization_anchor",
          "start_line": 487,
          "symbol": "SparseMatrix.read(InputStream)"
        },
        {
          "end_line": 485,
          "file": "math/src/main/java/com/powsybl/math/matrix/SparseMatrix.java",
          "span_kind": "sparsematrix_serialization_format_anchor",
          "start_line": 478,
          "symbol": "SparseMatrix.write(OutputStream)"
        },
        {
          "end_line": 30,
          "file": "math/src/main/java/com/powsybl/math/matrix/SparseMatrix.java",
          "span_kind": "serializable_class_anchor",
          "start_line": 21,
          "symbol": "SparseMatrix implements Serializable"
        }
      ],
      "case_id": "case::4b6b607a6ac5da006536",
      "cve_ids": [
        "CVE-2025-47771"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "powsybl__powsybl-core::CVE-2025-47771",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "SparseMatrix implements Serializable and declares a serialVersionUID, establishing Java native serialization as part of the class behavior.",
        "The writer serializes the SparseMatrix instance with ObjectOutputStream.writeObject(this), defining the expected serialized format consumed by read.",
        "The vulnerable read path creates ObjectInputStream from the supplied InputStream and immediately invokes readObject before any type filtering or validation."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "The code deserializes untrusted data using Java's default deserialization mechanisms (ObjectInputStream, XStream, Kryo) without restricting which classes can be instantiated. This allows attackers to craft malicious serialized objects that instantiate arbitrary classes, often leading to remote code execution via gadget chains. Various fixes involve adding class allowlists, replacing deserialization with safe parsing, removing serializable interfaces, disabling endpoints, or removing vulnerable libraries.",
  "guideline_group_key": "cluster_0016__mech_deserialization_untrusted_type_graph",
  "guideline_id": "gl_mech_0079",
  "guideline_text": "Trace untrusted serialized bytes, object streams, pickles, marshaled payloads, or type metadata into deserializers that instantiate classes, reconstruct object graphs, or invoke callbacks during object creation. Report code paths where allowed classes, object types, and construction side effects are not constrained before deserialization. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 15 historical CVE example(s), not as a project-specific signature. A safe implementation should use type allowlists, safe codecs, signature checks, or data-only formats instead of general object deserialization.",
  "mechanism": {
    "family": "deserialization",
    "mechanism_id": "mech_deserialization_untrusted_type_graph",
    "name": "untrusted deserialization with attacker-controlled type graph"
  },
  "structural_sanity": {
    "assigned_case_count": 3,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.6667,
    "flags": [
      "mixed_hcvr",
      "mixed_cwe"
    ],
    "metadata_cve_count": 3,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 0.6667,
    "source_cve_count": 15
  }
}