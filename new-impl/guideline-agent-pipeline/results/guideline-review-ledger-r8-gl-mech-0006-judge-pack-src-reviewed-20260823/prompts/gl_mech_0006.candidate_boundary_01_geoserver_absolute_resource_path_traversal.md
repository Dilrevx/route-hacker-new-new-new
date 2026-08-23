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
    "boundary_label": "candidate_boundary_01_geoserver_absolute_resource_path_traversal",
    "boundary_text": "Absolute resource wrapper path traversal: a REST upload, harvest, or resource-management path accepts attacker-controlled file names or resource path fragments and resolves them through a filesystem or URL-backed resource wrapper that is intended to represent an existing absolute location outside the normal data-directory resource implementation. Report paths where traversal components such as `..` are accepted by the wrapper and then used for read, write, directory, listing, deletion, harvest, or catalog import effects before path-component validation proves the child resource remains under the intended resource root.",
    "evidence_refs": [
      {
        "identity_key": "geoserver__geoserver::CVE-2023-51444",
        "source_evidence": "GitHub advisory GHSA-9v5q-2gwq-q9hq describes an arbitrary file upload in GeoServer's REST Coverage Store API. It states that relative-path coverage stores use a Resource implementation with traversal validation, while absolute-path coverage stores use a different Resource implementation that does not prevent path traversal. The PoC uses the REST endpoint with `filename=../../../../../../../../../../file/to/write`."
      },
      {
        "identity_key": "geoserver__geoserver::CVE-2023-51444",
        "source_evidence": "Pre-patch source at parent 447e1fcf778aaca1057f0f248d5a95752d39d8b1, `src/platform/src/main/java/org/geoserver/platform/resource/Files.java` lines 49-50, constructs `ResourceAdaptor(File file)` by storing `file.getAbsoluteFile()` without validation; lines 201-202 implement `get(String resourcePath)` as `new ResourceAdaptor(new File(file, resourcePath))`."
      },
      {
        "identity_key": "geoserver__geoserver::CVE-2023-51444",
        "source_evidence": "Pre-patch source at the same parent, `src/platform/src/main/java/org/geoserver/platform/resource/URIs.java` lines 30-31, stores the URL without validating `url.getPath()`; the resource later exposes the URL path and opens streams from it."
      },
      {
        "identity_key": "geoserver__geoserver::CVE-2023-51444",
        "source_evidence": "GeoServer PR #7222 is titled `[GEOS-11176] Add validation to file wrapper resource paths` and says it validates file wrapper resource paths to prevent using `..` in the path. Commit ca683170c669718cb6ad4c79e01b0451065e13b8 adds `valid(file.getPath())`, validates `resourcePath` in `get`, validates URL paths in `URIs`, and adds traversal tests. Backport commit fe235b3bb1d7f05751a4a2ef5390c36f5c9e78ae carries the same patch."
      }
    ],
    "exploit_precondition": "An authenticated GeoServer administrator or lower-privileged administrator with coverage-store modification permission can create or modify a coverage store that uses an absolute file URL, then upload or harvest a file with traversal components in the request `filename` parameter. The server process must have filesystem permissions over the target location reached by the escaped path.",
    "guideline_id": "gl_mech_0006",
    "mechanism_id": "mech_absolute_resource_path_traversal_missing_component_validation",
    "mechanism_name": "absolute resource wrapper path traversal through missing component validation",
    "missing_guard": "The absolute Resource wrapper path lacks a component-level traversal guard before constructing or wrapping file and URL resources. Pre-patch `Files.ResourceAdaptor(File file)` does not validate `file.getPath()`, `Files.ResourceAdaptor.get(String resourcePath)` passes `resourcePath` directly into `new File(file, resourcePath)`, and `URIs.ResourceAdaptor(URL url)` accepts `url.getPath()` without `Paths.valid`. The normal relative resource implementation's traversal validation therefore does not protect absolute-path coverage stores.",
    "rationale": "The authoritative advisory, PR, pre-patch source, and patch all point to filesystem path traversal through absolute resource wrapper validation gaps. The original request-body/path-scoped authorization wording would mislead both retrieval and audit toward body-selected object mismatch patterns that are not present in this case.",
    "recall_follow_up": "This is a source-only representative not present in the 143-case `new_unified_cases.v1.jsonl` identity set. Do not count it in same-identity recall metrics unless the frozen evaluation identity set is expanded and candidate slices are materialized. If this corrected boundary changes recall-consumed sidecar text, rerun same-identity recall for the fixed identity set and report it as a semantic correction to gl_mech_0006 rather than an authorization-mismatch gain.",
    "representative_cases": [
      "geoserver__geoserver::CVE-2023-51444"
    ],
    "reviewer_notes": "This row corrects the r8 attribution for the GeoServer member of gl_mech_0006. The evidence does not support `request-body resource identifiers bypass path-scoped authorization`; it supports missing traversal validation in the absolute file/URL Resource wrapper used by REST coverage-store upload paths. Keep this boundary separate from request-body authorization mismatch and from generic path traversal buckets unless their representative evidence shares the same absolute resource wrapper failure mode.",
    "safe_fix_semantics": "Apply path-component validation to every file or URL resource wrapper path before the resource is used. The observed fix calls `valid(file.getPath())` in the file-backed `ResourceAdaptor` constructor, calls `valid(resourcePath)` before `new File(file, resourcePath)`, and calls `Paths.valid(url.getPath())` in the URL-backed wrapper constructor. The helper rejects any `..` component after separator normalization, and tests cover Unix and Windows traversal forms.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The resulting resource reaches sensitive filesystem-backed effects in the coverage-store upload/harvest path. The advisory PoC uploads arbitrary contents through a coverage store and supplies `filename=../../.../file/to/write`; the vulnerable resource wrapper can then read, write, create directories, list, delete, or pass harvested resources outside the intended coverage-store directory. The impact includes arbitrary file upload and potential remote code execution or overwriting security files.",
    "source_shape": "GeoServer's REST Coverage Store API accepts upload requests with a request-controlled `filename` parameter and can operate on coverage stores configured with absolute file URLs. In the vulnerable source, absolute file references are adapted through `org.geoserver.platform.resource.Files.ResourceAdaptor` and `URIs.ResourceAdaptor`. The file-backed wrapper constructor stores `file.getAbsoluteFile()` and `get(String resourcePath)` creates `new File(file, resourcePath)` from the supplied child path."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.