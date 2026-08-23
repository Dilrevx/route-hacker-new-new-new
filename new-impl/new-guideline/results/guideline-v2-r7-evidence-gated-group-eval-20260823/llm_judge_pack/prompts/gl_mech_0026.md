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
          "end_line": 162,
          "file": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java",
          "span_kind": "phase21_004_review_entry_window",
          "start_line": 103,
          "symbol": ""
        },
        {
          "end_line": 133,
          "file": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java",
          "span_kind": "file_region",
          "start_line": 131,
          "symbol": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java:103-162.center_window_3"
        },
        {
          "end_line": 134,
          "file": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java",
          "span_kind": "file_region",
          "start_line": 130,
          "symbol": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java:103-162.center_window_5"
        },
        {
          "end_line": 135,
          "file": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java",
          "span_kind": "file_region",
          "start_line": 129,
          "symbol": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java:103-162.center_window_7"
        },
        {
          "end_line": 137,
          "file": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java",
          "span_kind": "file_region",
          "start_line": 127,
          "symbol": "one-java-agent-plugin/src/main/java/com/alibaba/oneagent/utils/IOUtils.java:103-162.center_window_11"
        }
      ],
      "case_id": "case::c06dc7390d539f02f5b9",
      "cve_ids": [
        "CVE-2022-25842"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "alibaba__one-java-agent::CVE-2022-25842",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 225,
          "file": "src/main/java/bspkrs/mmv/RemoteZipHandler.java",
          "span_kind": "hunk",
          "start_line": 220,
          "symbol": ""
        }
      ],
      "case_id": "case::884d23d35be5e00521a0",
      "cve_ids": [
        "CVE-2022-4494"
      ],
      "cwe_ids": [
        "CWE-22"
      ],
      "identity_key": "bspkrs__mcpmappingviewer::CVE-2022-4494",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 90,
          "file": "testng-core/src/main/java/org/testng/JarFileUtils.java",
          "span_kind": "primary_zip_entry_path_traversal_anchor",
          "start_line": 68,
          "symbol": "JarFileUtils.testngXmlExistsInJar"
        },
        {
          "end_line": 58,
          "file": "testng-core/src/main/java/org/testng/reporters/Files.java",
          "span_kind": "filesystem_write_sink_anchor",
          "start_line": 45,
          "symbol": "Files.copyFile"
        },
        {
          "end_line": 65,
          "file": "testng-core/src/main/java/org/testng/JarFileUtils.java",
          "span_kind": "jar_suite_entry_anchor",
          "start_line": 46,
          "symbol": "JarFileUtils.extractSuitesFrom"
        }
      ],
      "case_id": "case::94b8f375bd19bc5fdba4",
      "cve_ids": [
        "CVE-2022-4065"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "cbeust__testng::CVE-2022-4065",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "extractSuitesFrom is the jar-suite entry flow: it receives a jar file, logs that it is opening it, and calls testngXmlExistsInJar(jarFile, classes). This connects the externally supplied jar artifact to the vulnerable XML extraction helper named by NVD.",
        "testngXmlExistsInJar opens the jar, iterates JarEntry objects, treats parseable XML names as suite XML candidates, obtains an InputStream for the entry, constructs File copyFile = new File(tempDir, jeName), and calls Files.copyFile without validating the normalized destination path.",
        "If the copied entry matches xmlPathInJar, suitePath is set to the copied filesystem path and later parsed by Parser.parse. This makes the extracted XML file part of TestNG suite processing and matches the advisory's XML file parser component."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 310,
          "file": "src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java",
          "span_kind": "method_hunk",
          "start_line": 303,
          "symbol": "AbstractUnArchiver.extractFile.entryNameResolution"
        },
        {
          "end_line": 348,
          "file": "src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java",
          "span_kind": "method_hunk",
          "start_line": 318,
          "symbol": "AbstractUnArchiver.extractFile.writeOrCreateTarget"
        }
      ],
      "case_id": "case::ae127d0cf4929e7b2482",
      "cve_ids": [
        "CVE-2018-1002200"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "codehaus-plexus__plexus-archiver::CVE-2018-1002200",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "extractFile() receives the archive entryName and resolves it directly with FileUtils.resolveFile(dir, entryName). A traversal entry such as ../outside can therefore select a target outside the intended extraction directory before any containment check is performed.",
        "After resolving the target File, the vulnerable code creates parent directories, creates a symbolic link, creates a directory, or opens FileOutputStream(f) and copies attacker-controlled archive bytes to that path without verifying the target is below the extraction directory.",
        "The method proceeds to set metadata and chmod on the resolved target, confirming that the previously resolved file is treated as the authoritative extraction output even when entryName escaped the destination."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 165,
          "file": "qtiworks-engine/src/main/java/uk/ac/ed/ph/qtiworks/services/AssessmentPackageFileImporter.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 160,
          "symbol": ""
        }
      ],
      "case_id": "case::5b0245be9c691116749e",
      "cve_ids": [
        "CVE-2022-39367"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "davemckain__qtiworks::CVE-2022-39367",
      "primary_hcvr_type": "path_archive_traversal",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 183,
          "file": "src/main/java/com/diffplug/gradle/ZipMisc.java",
          "span_kind": "phase21_002_review_entry_window",
          "start_line": 178,
          "symbol": ""
        }
      ],
      "case_id": "case::87df02f6064e911ef81e",
      "cve_ids": [
        "CVE-2022-26049"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "diffplug__goomph::CVE-2022-26049",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 136,
          "file": "1.x/src/rogatkin/web/WarRoller.java",
          "span_kind": "hunk",
          "start_line": 131,
          "symbol": ""
        }
      ],
      "case_id": "case::d094d1026d41a1f9f5cb",
      "cve_ids": [
        "CVE-2022-4594"
      ],
      "cwe_ids": [
        "CWE-22"
      ],
      "identity_key": "drogatkin__tjws2::CVE-2022-4594",
      "primary_hcvr_type": "unspecified",
      "trace_evidence": [],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 2098,
          "file": "dspace-api/src/main/java/org/dspace/app/itemimport/ItemImport.java",
          "span_kind": "primary_saf_zip_entry_extraction_anchor",
          "start_line": 1994,
          "symbol": "ItemImport.unzip(File,String)"
        },
        {
          "end_line": 2078,
          "file": "dspace-api/src/main/java/org/dspace/app/itemimport/ItemImport.java",
          "span_kind": "zip_entry_file_write_anchor",
          "start_line": 2074,
          "symbol": "ItemImport.unzip FileOutputStream"
        },
        {
          "end_line": 2235,
          "file": "dspace-api/src/main/java/org/dspace/app/itemimport/ItemImport.java",
          "span_kind": "saf_import_unzip_call_anchor",
          "start_line": 2210,
          "symbol": "ItemImport.processUIImport SAF unzip calls"
        },
        {
          "end_line": 2020,
          "file": "dspace-api/src/main/java/org/dspace/app/itemimport/ItemImport.java",
          "span_kind": "zip_extraction_root_setup_anchor",
          "start_line": 2002,
          "symbol": "ItemImport.unzip destinationDir/zipDir setup"
        }
      ],
      "case_id": "case::6efeb12792a0ee5a5fa4",
      "cve_ids": [
        "CVE-2022-31195"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dspace__dspace::CVE-2022-31195",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "processUIImport() prepares per-user batch import paths for Simple Archive Format imports. Remote SAF uses data.zip under the import directory, and SAF upload copies the uploaded ZIP filename into the same import directory before extraction.",
        "Both remote SAF and safupload modes feed the resulting ZIP file into ItemImport.unzip(new File(dataPath), dataDir), so attacker-controlled archive entries reach the vulnerable extraction loop.",
        "unzip() chooses destinationDir, creates the temp extraction directory, and builds sourcedir and zipDir through string concatenation; this zipDir is later prepended directly to ZIP entry names."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster consists of vulnerabilities in archive extraction (ZIP, TAR, RAR) that allow directory traversal, arbitrary file write, or infinite loops. The most common root cause is the assumption that entry names are safe relative paths without canonicalization, enabling '..' sequences to escape the extraction directory. Other variants include insufficient string-based prefix checks, missing backslash normalization, symlink bypass, and missing cycle/null checks causing infinite loops.",
  "guideline_group_key": "cluster_0004__mech_path_traversal_missing_canonical_prefix",
  "guideline_id": "gl_mech_0026",
  "guideline_text": "Trace attacker-controlled filenames, archive entries, path fragments, or resource names into file read, write, delete, extraction, or resource-loading APIs. Report code paths where the normalized absolute path is not checked to remain under the intended base directory before the file operation. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 38 historical CVE example(s), not as a project-specific signature. A safe implementation should normalize and canonicalize the resolved path, then enforce a base-directory prefix or equivalent containment check.",
  "mechanism": {
    "family": "filesystem",
    "mechanism_id": "mech_path_traversal_missing_canonical_prefix",
    "name": "path traversal through missing canonical prefix check"
  },
  "structural_sanity": {
    "assigned_case_count": 14,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.7143,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 14,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 0.5,
    "source_cve_count": 38
  }
}