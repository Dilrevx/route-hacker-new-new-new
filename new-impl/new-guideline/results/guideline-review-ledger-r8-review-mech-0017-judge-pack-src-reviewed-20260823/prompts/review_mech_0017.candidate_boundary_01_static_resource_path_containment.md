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
    "boundary_label": "candidate_boundary_01_static_resource_path_containment",
    "boundary_text": "Static resource path traversal: an HTTP request path, servlet path, route path, or static-resource lookup key is decoded or trimmed and then resolved against a server-controlled static-resource root, user-file folder, mounted resource, or repository lookup before the final normalized filesystem/resource location is proven to remain inside the intended root. Report code paths where traversal segments, decoded traversal, absolute path behavior, or mount-prefix fallback can make a static-file read resolve outside the configured web resource base.",
    "evidence_refs": [
      {
        "identity_key": "openhab__openhab-webui::CVE-2024-42468",
        "source_evidence": "Public CVE metadata in assets/vulndb describes an unauthenticated CometVisuServlet path traversal where local files can be requested via HTTP GET before openHAB 4.2.1. Pre-patch checkout 091d0edc06862bb40a70d74a2d607d1366ce134d CometVisuServlet.java lines 181-197 reads req.getPathInfo(), URL-decodes it, builds new File(userFileFolder, decodedPath) and fallback new File(rootFolder, decodedPath), then doGet lines 139-178 serves requestedFile with processStaticRequest without a canonical containment check."
      },
      {
        "identity_key": "openhab__openhab-webui::CVE-2024-42468",
        "source_evidence": "Fix commit 630e8525835c698cf58856aa43782d92b18087f2 changes CometVisuServlet.getRequestedFile so after constructing each decoded File it rejects values whose canonical path does not start with userFileFolder.getCanonicalPath()+File.separator or rootFolder.getCanonicalPath()+File.separator, and doGet returns 404 when getRequestedFile returns null."
      },
      {
        "identity_key": "opensolon__solon::CVE-2025-1584",
        "source_evidence": "Public CVE metadata in assets/vulndb says Solon up to 3.0.8 has path traversal '../filedir' in solon-web-staticfiles StaticMappings.java. Pre-patch checkout 87474726f1e496b381ce9d5ebbadabd0e04c2d75 StaticMappings.find lines 68-96 iterates static locations, checks path.startsWith(m.pathPrefix), and calls repository.find(path.substring(...)) or repository.find(path.substring(1)) without rejecting traversal segments."
      },
      {
        "identity_key": "opensolon__solon::CVE-2025-1584",
        "source_evidence": "Fix commit f46e47fd1f8455b9467d7ead3cdb0509115b2ef1 wraps StaticMappings.find in if (path.contains(\"/../\") == false) with a patch comment saying '/../' is unsafe and forbidden before entering the static repository."
      }
    ],
    "exploit_precondition": "An unauthenticated or remote requester can choose a path handled by the static-resource servlet or static mapping, and the server has readable files reachable through decoded traversal or resource lookup behavior outside the intended static-resource root.",
    "guideline_id": "review_mech_0017",
    "mechanism_id": "mech_static_resource_path_traversal_missing_final_containment",
    "mechanism_name": "static resource request path traversal without final containment guard",
    "missing_guard": "The vulnerable OpenHAB code did not compare the canonical resolved file path against the canonical userFileFolder/rootFolder before serving it. The vulnerable Solon code did not reject '/../' traversal segments before selecting a StaticRepository and calling repository.find on the derived relative path. In both cases, the guard must be applied to the same final path value that reaches the static-resource read.",
    "rationale": "Both representative cases are static-resource file read paths where attacker-controlled request paths reach resource resolution before the final decoded or traversal-bearing path is constrained to the intended root.",
    "recall_follow_up": "After this boundary is promoted into recall-consumed sidecar text, rerun same-identity recall for openhab__openhab-webui::CVE-2024-42468 and opensolon__solon::CVE-2025-1584 at Top-100, Top-150, and Top-200. If recall misses, inspect whether candidate windows include CometVisuServlet.getRequestedFile/doGet and StaticMappings.find before weakening the semantic boundary.",
    "representative_cases": [
      "openhab__openhab-webui::CVE-2024-42468",
      "opensolon__solon::CVE-2025-1584"
    ],
    "reviewer_notes": "This boundary intentionally uses static-resource request path and final containment wording rather than the older broad 'missing path validation' template. It should not absorb upload filename traversal, archive extraction, or recursive copy/move ancestor checks unless the source and sink are a request path resolved for static serving.",
    "safe_fix_semantics": "Before returning or serving the resource, normalize/canonicalize the final resolved path and enforce containment under the intended root, or reject traversal segments before repository lookup when that lookup is the authoritative resolution step. The check must occur after URL decoding and before the file or URL is returned to the response path.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The resolved File or URL is then used to serve static content to the client. In OpenHAB, doGet calls processStaticRequest(requestedFile, req, resp, true) for the resolved file. In Solon, StaticMappings.find returns the repository URL for the requested resource, allowing the static-file handling path to read the selected resource.",
    "source_shape": "The reviewed cases take a remote HTTP path or static-resource lookup path and pass it into a static resource resolver. OpenHAB CometVisuServlet.getRequestedFile reads req.getPathInfo(), URL-decodes it, and constructs File objects under userFileFolder and rootFolder. Solon StaticMappings.find receives a path argument and dispatches it to the matching StaticRepository by stripping a prefix or leading slash."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.