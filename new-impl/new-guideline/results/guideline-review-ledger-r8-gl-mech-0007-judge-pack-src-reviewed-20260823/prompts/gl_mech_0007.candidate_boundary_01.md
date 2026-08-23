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
    "boundary_label": "candidate_boundary_01",
    "boundary_text": "Untrusted URL download SSRF: a request parameter or equivalent caller-controlled URL argument is used as the destination for a server-side Java URL.openStream, URLConnection, HTTP client, download helper, or proxy fetch before the same path parses and constrains the outbound scheme and destination. The checked instance is a download endpoint where the request-supplied URL remains the fetched URL unless private OSS mode rewrites it.",
    "evidence_refs": [
      {
        "identity_key": "feiyuchuixue__sz-boot-parent::CVE-2026-3189",
        "source_evidence": "Remote old source archive /data/lhq/workspace/route-hacker-lineage-integration-20260803/output/hcvr_new_unified_external_baselines_v1/source_acquisition_r33_missing_offset125_limit100/archives/feiyuchuixue__sz-boot-parent__72dab1d0196f.tar.gz contains sz-service/sz-service-admin/src/main/java/com/sz/admin/system/service/impl/CommonServiceImpl.java. Lines 146-160 define urlDownload(String url,...): it rejects only null/empty url, derives bucket/object/filename, assigns String fileUrl = url, conditionally rewrites private OSS URLs, then calls new URL(fileUrl).openStream()."
      },
      {
        "identity_key": "feiyuchuixue__sz-boot-parent::CVE-2026-3189",
        "source_evidence": "Remote patch cache /data/lhq/workspace/route-hacker/output/cve_clustering/v2/patch_cache/aefaabfd7527188bfba3c8c9eee17c316d094802.diff shows the CommonServiceImpl hunk replacing direct new URL(fileUrl).openStream() with URL parsedUrl = new URL(fileUrl), malformed URL handling, protocol extraction, rejection unless protocol is http or https, and parsedUrl.openStream(). The same patch also adds OSS allowedExts and allowedMimeTypes configuration and helper methods."
      },
      {
        "identity_key": "feiyuchuixue__sz-boot-parent::CVE-2026-3189",
        "source_evidence": "Local unified dataset trace for case::84a39bdc311e873b9594 records the same old source hash aa6afad94bd34d9e07323f923cc7c854453540ef8c6cb874e588a8a2526e1120, the old source span CommonServiceImpl.java lines 143-160, and the patch-cache evidence that direct openStream was replaced by URL parsing plus protocol validation before openStream."
      }
    ],
    "exploit_precondition": "An attacker can call the file download path with a URL value or otherwise influence the url argument consumed by CommonServiceImpl.urlDownload, and the server environment can reach destinations that should not be reachable from the attacker directly.",
    "guideline_id": "gl_mech_0007",
    "mechanism_id": "mech_ssrf_untrusted_url_download_openstream",
    "mechanism_name": "server-side URL download fetch from attacker-controlled URL",
    "missing_guard": "Before the fix, the urlDownload path checked only null/empty input and parsed path segments for OSS bucket/object helpers. It did not create a URL object and enforce an allowed protocol before openStream, and the reviewed evidence does not show host, DNS-resolved IP, private-network, metadata-address, or redirect-hop policy on the fetched destination.",
    "rationale": "The source-reviewed evidence supports a generic attacker-controlled URL download fetch boundary. It does not require webhook/callback semantics, and it only proves the concrete missing protocol guard plus absent visible destination policy on the shown old path.",
    "recall_follow_up": "If this boundary changes recall-consumed guideline text, rerun same-identity P3C64 recall for feiyuchuixue__sz-boot-parent::CVE-2026-3189 and then the frozen 143 identity set at Top-100, Top-150, and Top-200. Inspect whether the query retrieves CommonServiceImpl.urlDownload and nearby download helpers without using known anchors, labels, or regex fallback.",
    "representative_cases": [
      "feiyuchuixue__sz-boot-parent::CVE-2026-3189"
    ],
    "safe_fix_semantics": "The patch parses fileUrl with new URL(fileUrl), rejects malformed URLs, rejects protocols other than http and https, and then calls parsedUrl.openStream() on the parsed URL. MIME type and extension allowlists are also added elsewhere, but those are content controls rather than destination controls. A stronger production SSRF fix would add host allowlists, DNS/IP private-range checks, and redirect revalidation before the same outbound request.",
    "schema_version": "hcvr_guideline_review_ledger.v1",
    "sink_or_sensitive_effect": "The old-side fileUrl reaches new URL(fileUrl).openStream() inside CommonServiceImpl.urlDownload, so the server opens an outbound URL and streams the response to the client. Adjacent context in tempDownload also uses new URL(fileUrl).openStream() for stored UploadResult or private OSS URLs, but that stored-resource path is not promoted by this row.",
    "source_shape": "The public download helper CommonServiceImpl.urlDownload receives a caller-provided String url, derives bucket/object/filename metadata from that same string, keeps fileUrl equal to url when oss.accessMode is not private, and prepares a server-side download response."
  },
  "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above."
}

Return JSON only. Do not call tools or run commands.