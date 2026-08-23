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
          "end_line": 47,
          "file": "src/main/java/org/dstadler/jgit/porcelain/CleanUntrackedFiles.java",
          "span_kind": "phase2_review_entry_window",
          "start_line": 45,
          "symbol": "CleanUntrackedFiles.main"
        }
      ],
      "case_id": "case::50c3bb9fac0188ac0b12",
      "cve_ids": [
        "CVE-2022-4817"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "centic9__jgit-cookbook::CVE-2022-4817",
      "primary_hcvr_type": "toctou_check_use_race",
      "trace_evidence": [
        "Old-side patch hunk creates a temp file, deletes it, then mkdirs the same path under the repository work tree. The fixed-side source now uses Files.createTempDirectory."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 104,
          "file": "globalpomutils-fileresources/src/main/java/com/anrisoftware/globalpom/fileresourcemanager/FileResourceManagerProvider.java",
          "span_kind": "phase2_review_entry_window",
          "start_line": 96,
          "symbol": "FileResourceManagerProvider.createTmpDir"
        }
      ],
      "case_id": "case::70b89cde877178f66088",
      "cve_ids": [
        "CVE-2018-25068"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "devent__globalpom-utils::CVE-2018-25068",
      "primary_hcvr_type": "toctou_check_use_race",
      "trace_evidence": [
        "Old-side patch hunk creates a temp file, deletes it, then mkdirs the same path. The fixed-side source now uses Files.createTempDirectory, so this label is explicitly patch-backed."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 233,
          "file": "hawtjni-runtime/src/main/java/org/fusesource/hawtjni/runtime/Library.java",
          "span_kind": "phase1_review_entry_window",
          "start_line": 204,
          "symbol": "Library.exractAndLoad"
        },
        {
          "end_line": 320,
          "file": "hawtjni-runtime/src/main/java/org/fusesource/hawtjni/runtime/Library.java",
          "span_kind": "phase1_review_entry_window",
          "start_line": 313,
          "symbol": "Library.load(File)"
        },
        {
          "end_line": 281,
          "file": "hawtjni-runtime/src/main/java/org/fusesource/hawtjni/runtime/Library.java",
          "span_kind": "phase1_review_entry_window",
          "start_line": 263,
          "symbol": "Library.extract"
        }
      ],
      "case_id": "case::aacd87928b32cf3c8e84",
      "cve_ids": [
        "CVE-2013-2035"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "fusesource__hawtjni::CVE-2013-2035",
      "primary_hcvr_type": "toctou_check_use_race",
      "trace_evidence": [
        "Manual repair confirms a TOCTOU source contract over the same-or-derived temp native library object: the old flow chooses a temp directory, creates/writes/chmods a temp file, and then uses that derived path in System.load. This checkpoint repairs source-contract metadata only; it does not add labels, run retrieval, or claim dynamic exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 9,
          "file": "src/main/java/org/junit/rules/TemporaryFolder.java",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 4,
          "symbol": ""
        },
        {
          "end_line": 235,
          "file": "src/main/java/org/junit/rules/TemporaryFolder.java",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 229,
          "symbol": ""
        }
      ],
      "case_id": "case::b447208319c27a0a66e4",
      "cve_ids": [
        "CVE-2020-15250"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "junit-team__junit4::CVE-2020-15250",
      "primary_hcvr_type": "file_permission_temp_resource",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 14,
          "file": "microservices/launcher/src/main/java/com/manydesigns/portofino/microservices/launcher/WarFileLauncher.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 9,
          "symbol": ""
        },
        {
          "end_line": 88,
          "file": "microservices/launcher/src/main/java/com/manydesigns/portofino/microservices/launcher/WarFileLauncher.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 80,
          "symbol": ""
        }
      ],
      "case_id": "case::84b4acd1aee2fe945841",
      "cve_ids": [
        "CVE-2022-3952"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "manydesigns__portofino::CVE-2022-3952",
      "primary_hcvr_type": "file_permission_temp_resource",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 78,
          "file": "src/main/java/com/openkm/util/FileUtils.java",
          "span_kind": "phase3_2_review_entry_window",
          "start_line": 66,
          "symbol": "FileUtils.createTempDir"
        }
      ],
      "case_id": "case::262d118f09c91080a049",
      "cve_ids": [
        "CVE-2022-3969"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "openkm__document-management-system::CVE-2022-3969",
      "primary_hcvr_type": "toctou_check_use_race",
      "trace_evidence": [
        "Old-side patch hunk creates a temporary file, deletes it, and then mkdirs the same path. This is a clear check/use race-sensitive resource creation sequence; fixed source uses Files.createTempDirectory."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 22,
          "file": "pgjdbc/src/main/java/org/postgresql/util/StreamWrapper.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 17,
          "symbol": ""
        },
        {
          "end_line": 57,
          "file": "pgjdbc/src/main/java/org/postgresql/util/StreamWrapper.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 51,
          "symbol": ""
        },
        {
          "end_line": 20,
          "file": "pgjdbc/src/main/java/org/postgresql/util/StreamWrapper.java",
          "span_kind": "file_region",
          "start_line": 18,
          "symbol": "pgjdbc/src/main/java/org/postgresql/util/StreamWrapper.java:17-22.center_window_3"
        },
        {
          "end_line": 21,
          "file": "pgjdbc/src/main/java/org/postgresql/util/StreamWrapper.java",
          "span_kind": "file_region",
          "start_line": 17,
          "symbol": "pgjdbc/src/main/java/org/postgresql/util/StreamWrapper.java:17-22.center_window_5"
        },
        {
          "end_line": 22,
          "file": "pgjdbc/src/main/java/org/postgresql/util/StreamWrapper.java",
          "span_kind": "file_region",
          "start_line": 16,
          "symbol": "pgjdbc/src/main/java/org/postgresql/util/StreamWrapper.java:17-22.center_window_7"
        }
      ],
      "case_id": "case::a27bb6d20b75ed1333ce",
      "cve_ids": [
        "CVE-2022-41946"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "pgjdbc__pgjdbc::CVE-2022-41946",
      "primary_hcvr_type": "file_permission_temp_resource",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 185,
          "file": "modules/swagger-generator/src/main/java/io/swagger/generator/online/Generator.java",
          "span_kind": "function",
          "start_line": 174,
          "symbol": "getTmpFolder"
        },
        {
          "end_line": 186,
          "file": "modules/swagger-generator/src/main/java/io/swagger/generator/online/Generator.java",
          "span_kind": "sliding_window",
          "start_line": 121,
          "symbol": "Generator.getTmpFolder"
        },
        {
          "end_line": 178,
          "file": "modules/swagger-generator/src/main/java/io/swagger/generator/online/Generator.java",
          "span_kind": "file_region",
          "start_line": 176,
          "symbol": "Generator.getTmpFolder.center_window_3"
        },
        {
          "end_line": 179,
          "file": "modules/swagger-generator/src/main/java/io/swagger/generator/online/Generator.java",
          "span_kind": "file_region",
          "start_line": 175,
          "symbol": "Generator.getTmpFolder.center_window_5"
        },
        {
          "end_line": 180,
          "file": "modules/swagger-generator/src/main/java/io/swagger/generator/online/Generator.java",
          "span_kind": "file_region",
          "start_line": 174,
          "symbol": "Generator.getTmpFolder.center_window_7"
        }
      ],
      "case_id": "case::6d914a332e5cb6d17876",
      "cve_ids": [
        "CVE-2021-21363"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "swagger-api__swagger-codegen::CVE-2021-21363",
      "primary_hcvr_type": "toctou_check_use_race",
      "trace_evidence": [
        "getTmpFolder creates a temporary file, deletes it, then creates a directory at the same path. That leaves a race window on the filesystem object between the check/creation boundary and use. The patch replaces the sequence with Files.createTempDirectory, so this is a source/patch-backed TOCTOU review-entry anchor."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster consists of vulnerabilities in Java and Python libraries where temporary files or directories are created using non-atomic operations (e.g., create, delete, mkdir sequence) that introduce TOCTOU race conditions, or using APIs that default to overly permissive permissions (world-readable), allowing local attackers to read sensitive data or perform symlink attacks. Additional variants include failing to verify permission changes, manually setting overly permissive permissions, and using predictable file names that enable race attacks.",
  "guideline_group_key": "cluster_0000__mech_temp_file_delete_mkdir_race",
  "guideline_id": "gl_mech_0001",
  "guideline_text": "Trace temporary file or directory names created in shared writable locations into manual temporary directory creation sequences such as createTempFile, delete, then mkdir or mkdirs. Report code paths where the temporary path is released between creation and directory creation, allowing another actor to replace or pre-create it before use. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 10 historical CVE example(s), not as a project-specific signature. A safe implementation should use an atomic temporary-directory API such as Files.createTempDirectory and avoid delete-then-mkdir sequences.",
  "judge_selection_reason": "label_mixed",
  "mechanism": {
    "family": "race_or_lifecycle",
    "mechanism_id": "mech_temp_file_delete_mkdir_race",
    "name": "temporary directory create-delete-mkdir TOCTOU race"
  },
  "structural_sanity": {
    "assigned_case_count": 8,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 8,
    "primary_hcvr_majority": "toctou_check_use_race",
    "primary_hcvr_purity": 0.625,
    "source_cve_count": 10
  }
}