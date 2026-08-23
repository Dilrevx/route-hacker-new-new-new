# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration, not as a hard scoring target.
Low scores and non-accept decisions identify groups worth reading; they should not be converted into keyword rules or hidden routing logic.

## Summary

- Judge inputs: 2
- Parsed outputs: 2
- Missing outputs: 0
- Invalid outputs: 0
- Accepted groups: 1
- Needs revision/split/merge/evidence: 1
- Low-score groups: 2 at threshold 0.6
- Decision counts: {'accept': 1, 'needs_evidence': 1}
- Average scores: {'coherence_score': 0.625, 'coverage_score': 0.275, 'actionability_score': 0.525, 'retrieval_query_quality': 0.55}

## Highest Priority Rows

- `gl_mech_0007` `mech_ssrf_webhook_or_callback_fetch`: decision=needs_evidence, min_score=0.0, issue=The mechanism describes a coherent webhook/callback SSRF pattern but has zero representative cases. The only reviewed evidence (CommonServiceImpl.urlDownload) supports direct file-download SSRF, not server-initiated callback or notification delivery to a user-selected endpoint. The source shape, sink shape, missing guard, exploit precondition, and safe fix are all described hypothetically without any case-level support.
- `gl_mech_0007` `mech_ssrf_untrusted_url_download_openstream`: decision=accept, min_score=0.55, issue=The boundary describes a coherent mechanism: attacker-controlled URL parameter flows to server-side URL.openStream without protocol or destination validation. The source shape (urlDownload receives String url, derives metadata, keeps fileUrl = url), sink (new URL(fileUrl).openStream()), missing guard (no protocol/host validation before openStream), and safe fix (parse URL, reject non-http/https protocols) are all consistent and evidenced. However, the guideline text mentions 'HTTP client, download helper, or proxy fetch' as sink variants, but only the download helper (openStream) variant is evidenced by the single representative case. Coverage is limited to one case, but the mechanism is well-defined and actionable.
