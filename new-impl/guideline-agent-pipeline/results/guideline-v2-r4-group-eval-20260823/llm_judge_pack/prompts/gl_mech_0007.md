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
          "end_line": 353,
          "file": "src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java",
          "span_kind": "primary_symlink_overwrite_fix_anchor",
          "start_line": 328,
          "symbol": "AbstractUnArchiver.extractFile target resolution"
        },
        {
          "end_line": 383,
          "file": "src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java",
          "span_kind": "symlink_then_file_write_anchor",
          "start_line": 355,
          "symbol": "AbstractUnArchiver.extractFile write paths"
        },
        {
          "end_line": 210,
          "file": "src/main/java/org/codehaus/plexus/archiver/zip/AbstractZipUnArchiver.java",
          "span_kind": "zip_physical_order_entry_anchor",
          "start_line": 181,
          "symbol": "AbstractZipUnArchiver.execute"
        },
        {
          "end_line": 120,
          "file": "src/main/java/org/codehaus/plexus/archiver/tar/TarUnArchiver.java",
          "span_kind": "tar_symlink_entry_anchor",
          "start_line": 102,
          "symbol": "TarUnArchiver.execute"
        }
      ],
      "case_id": "case::0db3b7c33c6267bbc4da",
      "cve_ids": [
        "CVE-2023-37460"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "codehaus-plexus__plexus-archiver::CVE-2023-37460",
      "primary_hcvr_type": "iris",
      "trace_evidence": [
        "ZIP extraction iterates ZipArchiveEntry objects in physical order, opens each entry stream, and passes entry name, mode, symlink destination from resolveSymlink(), and content stream into AbstractUnArchiver.extractFile().",
        "TAR extraction similarly reads TarArchiveEntry names and symlink targets, then delegates each selected entry to AbstractUnArchiver.extractFile().",
        "extractFile maps the attacker-controlled archive entry name to targetFileName and checks canonical path containment, but this block does not reject standard-file extraction to a path that is already a symbolic link."
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
    }
  ],
  "cluster_summary": "This cluster contains path traversal vulnerabilities in archive extraction routines (ZIP, TAR, APK) where untrusted entry names are used to construct file paths without proper canonicalization or containment verification. The primary root cause is the absence of a canonical path containment check, allowing attackers to write files outside the intended extraction directory via '..' sequences. Variants include flawed string-based prefix comparisons, separator normalization gaps, blacklist-only defenses, and symlink bypass scenarios.",
  "guideline_group_key": "cluster_0002__mech_path_traversal_missing_canonical_prefix",
  "guideline_id": "gl_mech_0007",
  "guideline_text": "Trace attacker-controlled filenames, archive entries, path fragments, or resource names into file read, write, delete, extraction, or resource-loading APIs. Report code paths where the normalized absolute path is not checked to remain under the intended base directory before the file operation. Confirm that the guard is enforced before the sensitive effect and remains bound to the same resource, principal, destination, or object that the effect uses. Treat this as a reusable mechanism-level pattern derived from 45 historical CVE example(s), not as a project-specific signature. A safe implementation should normalize and canonicalize the resolved path, then enforce a base-directory prefix or equivalent containment check.",
  "mechanism": {
    "family": "filesystem",
    "mechanism_id": "mech_path_traversal_missing_canonical_prefix",
    "name": "path traversal through missing canonical prefix check"
  },
  "structural_sanity": {
    "assigned_case_count": 19,
    "cwe_majority": "unspecified",
    "cwe_purity": 0.7895,
    "flags": [
      "mixed_hcvr"
    ],
    "metadata_cve_count": 19,
    "primary_hcvr_majority": "iris",
    "primary_hcvr_purity": 0.4211,
    "source_cve_count": 45
  }
}