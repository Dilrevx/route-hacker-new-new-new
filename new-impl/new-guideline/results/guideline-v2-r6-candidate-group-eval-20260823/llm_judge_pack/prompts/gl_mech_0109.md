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
          "end_line": 140,
          "file": "commons/src/main/java/com/powsybl/commons/datasource/DirectoryDataSource.java",
          "span_kind": "primary_datasource_polynomial_regex_anchor",
          "start_line": 123,
          "symbol": "DirectoryDataSource.listNames(String)"
        },
        {
          "end_line": 106,
          "file": "commons/src/main/java/com/powsybl/commons/datasource/ReadOnlyMemDataSource.java",
          "span_kind": "in_memory_datasource_regex_anchor",
          "start_line": 101,
          "symbol": "ReadOnlyMemDataSource.listNames(String)"
        },
        {
          "end_line": 207,
          "file": "commons/src/main/java/com/powsybl/commons/datasource/ZipArchiveDataSource.java",
          "span_kind": "archive_entry_regex_anchor",
          "start_line": 191,
          "symbol": "ZipArchiveDataSource.listNames(String)"
        }
      ],
      "case_id": "case::eabe5b3fef05b367ec2e",
      "cve_ids": [
        "CVE-2025-48058"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "powsybl__powsybl-core::CVE-2025-48058",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The filesystem DataSource listNames entrypoint compiles the caller-supplied regex with java.util.regex.Pattern and applies p.matcher(s).matches() to regular file names after compression-extension normalization.",
        "The vulnerable snapshot imports java.util.regex.Pattern in this production DataSource implementation, matching the fix commit replacement with com.google.re2j.Pattern.",
        "The in-memory DataSource implementation compiles the supplied regex with java.util.regex.Pattern and evaluates it against every stored key name."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 34,
          "file": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/RegexCriterion.java",
          "span_kind": "primary_regexcriterion_polynomial_redos_anchor",
          "start_line": 31,
          "symbol": "RegexCriterion.filter(Identifiable, IdentifiableType)"
        },
        {
          "end_line": 109,
          "file": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/json/CriterionDeserializer.java",
          "span_kind": "regex_criterion_input_construction_anchor",
          "start_line": 82,
          "symbol": "CriterionDeserializer regex field to RegexCriterion"
        },
        {
          "end_line": 43,
          "file": "iidm/iidm-criteria/src/main/java/com/powsybl/iidm/criteria/NetworkElementVisitor.java",
          "span_kind": "criterion_filter_dispatch_anchor",
          "start_line": 31,
          "symbol": "NetworkElementVisitor.doRespectCriterion"
        }
      ],
      "case_id": "case::b55de475720883cfe9c1",
      "cve_ids": [
        "CVE-2025-48059"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "powsybl__powsybl-core::CVE-2025-48059",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "The vulnerable snapshot imports java.util.regex.Pattern in RegexCriterion, the exact import replaced by the fix with com.google.re2j.Pattern.",
        "RegexCriterion stores the constructor-supplied regex string without validation or transformation before later compiling it during filtering.",
        "The vulnerable sink compiles the supplied regex with java.util.regex.Pattern.compile(regex) and runs matcher(identifiable.getId()).find() against the target Identifiable id."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "Six of the seven CVEs in this cluster involve denial of service through user-supplied regular expressions that trigger catastrophic backtracking. The root causes vary: using a backtracking regex engine (Java/JavaScript) without linear-time alternatives, lacking input validation or heuristic checks, or missing execution timeouts. The fixes accordingly include engine replacement, pattern validation, default literal search with explicit opt-in, and adding timeouts. One unrelated CVE concerns missing authorization for data stream indices.",
  "guideline_group_key": "cluster_0023__pending_mech_cluster_23_replace_backtracking_regex_engine_with_linear_time_alternative",
  "guideline_id": "gl_mech_0109",
  "guideline_text": "Trace attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs into the sensitive operation or security boundary described by the member CVEs. Report code paths where the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 3 historical CVE example(s), not as a project-specific signature. A safe implementation should Replace the engine with a linear-time alternative (e.g., Google's RE2/J for Java, RE2 library for JavaScript) that guarantees O(n) evaluation..",
  "mechanism": {
    "family": "pending_review",
    "mechanism_id": "pending_mech_cluster_23_replace_backtracking_regex_engine_with_linear_time_alternative",
    "name": "Replace backtracking regex engine with linear-time alternative"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "pending_review"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 3
  }
}