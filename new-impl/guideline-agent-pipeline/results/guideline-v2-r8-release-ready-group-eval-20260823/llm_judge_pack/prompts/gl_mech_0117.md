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
          "end_line": 230,
          "file": "plugins/auth-backend/src/service/CimdClient.ts",
          "span_kind": "phase21_014_review_entry_window",
          "start_line": 207,
          "symbol": "fetchCimdMetadata"
        }
      ],
      "case_id": "case::6408b5510d69ddd58773",
      "cve_ids": [
        "CVE-2026-32236"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "backstage__backstage::CVE-2026-32236",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.014 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 1080,
          "file": "src/blender_mcp/server.py",
          "span_kind": "sliding_window",
          "start_line": 1001,
          "symbol": "import_generated_asset_hunyuan"
        },
        {
          "end_line": 1120,
          "file": "src/blender_mcp/server.py",
          "span_kind": "sliding_window",
          "start_line": 1041,
          "symbol": "import_generated_asset_hunyuan"
        },
        {
          "end_line": 1160,
          "file": "src/blender_mcp/server.py",
          "span_kind": "sliding_window",
          "start_line": 1081,
          "symbol": "import_generated_asset_hunyuan"
        },
        {
          "end_line": 2280,
          "file": "addon.py",
          "span_kind": "sliding_window",
          "start_line": 2201,
          "symbol": "BlenderMCPServer.import_generated_asset_hunyuan_ai"
        },
        {
          "end_line": 2320,
          "file": "addon.py",
          "span_kind": "sliding_window",
          "start_line": 2241,
          "symbol": "BlenderMCPServer.import_generated_asset_hunyuan_ai"
        }
      ],
      "case_id": "case::24082e30c3043e929e0f",
      "cve_ids": [
        "CVE-2026-10662"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "bergskenop__blender-mcp::CVE-2026-10662",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "The MCP tool accepts caller-controlled zip_file_url and forwards it over the Blender socket as the import_generated_asset_hunyuan command argument. The patch adds destination validation on this bridge before forwarding, confirming it as the review-entry bridge from untrusted MCP input to the Blender-side network fetch.",
        "The Blender add-on validates only that zip_file_url starts with http(s), then calls requests.get(zip_file_url, stream=True). The patch adds validate_url_not_internal immediately before this download, making this the concrete URL-to-request SSRF sink for the case."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 54,
          "file": "packages/backend-core/src/blacklist/blacklist.ts",
          "span_kind": "phase21_033_review_entry_window",
          "start_line": 39,
          "symbol": "isBlacklisted DNS lookup and exact IP membership"
        },
        {
          "end_line": 44,
          "file": "packages/backend-core/src/blacklist/blacklist.ts",
          "span_kind": "phase21_033_review_entry_window",
          "start_line": 23,
          "symbol": "refreshBlacklist / isBlacklisted empty blacklist fail-open"
        }
      ],
      "case_id": "case::037470c3d85bb8b97b11",
      "cve_ids": [
        "CVE-2026-31818"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "budibase__budibase::CVE-2026-31818",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.031 materialized this label only after selecting a cached CVE intake backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 80,
          "file": "alerts/service_backends/webhook_security.py",
          "span_kind": "sliding_window",
          "start_line": 1,
          "symbol": "validate_webhook_url"
        },
        {
          "end_line": 89,
          "file": "alerts/service_backends/webhook_security.py",
          "span_kind": "sliding_window",
          "start_line": 41,
          "symbol": "validate_webhook_url"
        },
        {
          "end_line": 49,
          "file": "alerts/service_backends/webhook_security.py",
          "span_kind": "file_region",
          "start_line": 47,
          "symbol": "validate_webhook_url.center_window_3"
        },
        {
          "end_line": 50,
          "file": "alerts/service_backends/webhook_security.py",
          "span_kind": "file_region",
          "start_line": 46,
          "symbol": "validate_webhook_url.center_window_5"
        },
        {
          "end_line": 51,
          "file": "alerts/service_backends/webhook_security.py",
          "span_kind": "file_region",
          "start_line": 45,
          "symbol": "validate_webhook_url.center_window_7"
        }
      ],
      "case_id": "case::f1d6a55fe6af8547c23d",
      "cve_ids": [
        "CVE-2026-44502"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "bugsink__bugsink::CVE-2026-44502",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "validate_webhook_url uses urllib.parse.urlparse to decide scheme and hostname before outbound policy checks. The patch switches to requests preparation plus urllib3 parsing and rejects raw non-RFC characters, confirming this parser boundary as the review entry.",
        "The non-global IP guard is downstream of the parser-derived hostname. It remains review-worthy because parser disagreement can make this guard inspect a different host than the HTTP client sends to.",
        "The old code resolves parsed.hostname and matches allow/deny lists against hostname derived from urlparse. The advisory and patch describe parser disagreement with requests/urllib3, so this resolution and policy span is the concrete SSRF destination decision point."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 112,
          "file": "projects/core/src/main/java/dan200/computercraft/core/apis/http/options/AddressPredicate.java",
          "span_kind": "function",
          "start_line": 104,
          "symbol": "matches"
        },
        {
          "end_line": 112,
          "file": "projects/core/src/main/java/dan200/computercraft/core/apis/http/options/AddressPredicate.java",
          "span_kind": "function",
          "start_line": 107,
          "symbol": "matches"
        },
        {
          "end_line": 119,
          "file": "projects/core/src/main/java/dan200/computercraft/core/apis/http/options/AddressPredicate.java",
          "span_kind": "sliding_window",
          "start_line": 41,
          "symbol": "AddressPredicate.PrivatePattern.matches"
        }
      ],
      "case_id": "case::8d9d6c32273fbeedc344",
      "cve_ids": [
        "CVE-2023-37262"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "cc-tweaked__cc-tweaked::CVE-2023-37262",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "PrivatePattern.matches is the IP destination policy predicate used to deny private/internal addresses. The old code only checks any-local, loopback, link-local, and site-local addresses; the patch adds cloud metadata addresses, multicast, and unique-local IPv6 handling, confirming this predicate as the SSRF review entry."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 669,
          "file": "server/controllers/ConnectionController.js",
          "span_kind": "phase21_029_review_entry_window",
          "start_line": 648,
          "symbol": "ConnectionController.testRequest API request path"
        },
        {
          "end_line": 400,
          "file": "server/controllers/ConnectionController.js",
          "span_kind": "phase21_029_review_entry_window",
          "start_line": 398,
          "symbol": "ConnectionController.testApi"
        }
      ],
      "case_id": "case::7bfc1bbf01608241ced9",
      "cve_ids": [
        "CVE-2026-30232"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "chartbrew__chartbrew::CVE-2026-30232",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.029 materialized this label only after selecting a cached CVE intake backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 16,
          "file": "wavs/bridge/src/local-compute.ts",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 11,
          "symbol": ""
        },
        {
          "end_line": 109,
          "file": "wavs/bridge/src/local-compute.ts",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 96,
          "symbol": ""
        },
        {
          "end_line": 147,
          "file": "wavs/bridge/src/local-compute.ts",
          "span_kind": "phase21_001_review_entry_window",
          "start_line": 140,
          "symbol": ""
        }
      ],
      "case_id": "case::5dc5edc7a60303c5d1da",
      "cve_ids": [
        "CVE-2026-43993"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "dragonmonk111__junoclaw::CVE-2026-43993",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21 materialized this label from a source-ready case whose pre-patch source tree and patch-derived line anchor were verified. The label is a review-entry ground truth for retrieval/ranking, not proof of exploitability."
      ],
      "vulnerability_description": ""
    },
    {
      "anchor_examples": [
        {
          "end_line": 151,
          "file": "src/lib/plugins/media-generators/fal.ts",
          "span_kind": "phase21_019_review_entry_window",
          "start_line": 100,
          "symbol": "getFalRequestStatus and getFalRequestResult"
        }
      ],
      "case_id": "case::b342221d11d2a1f887f2",
      "cve_ids": [
        "CVE-2026-22664"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "f__prompts.chat::CVE-2026-22664",
      "primary_hcvr_type": "ssrf",
      "trace_evidence": [
        "Phase 21.019 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster contains 40 CVEs primarily related to Server-Side Request Forgery (SSRF) due to missing or incomplete validation of user-supplied URLs before making outbound HTTP requests. It also includes issues with TLS certificate validation, credential exposure, authorization context confusion, regular expression denial of service, and concurrency race conditions. The common thread is inadequate security checks in network-facing operations.",
  "guideline_group_key": "cluster_0070__mech_ssrf_webhook_url_fetch",
  "guideline_id": "gl_mech_0117",
  "guideline_text": "Trace attacker-controlled webhook URLs, callback URLs, endpoint parameters, or request destinations into outbound HTTP clients, URL.openConnection, fetch helpers, proxy clients, or webhook dispatchers. Report code paths where scheme, host, redirect target, DNS resolution, and private-address ranges are not constrained before the outbound request. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 58 historical CVE example(s), not as a project-specific signature. A safe implementation should enforce scheme and host allowlists, block private and metadata addresses after DNS resolution, and validate redirect targets.",
  "judge_selection_reason": "clean_control",
  "mechanism": {
    "family": "ssrf",
    "mechanism_id": "mech_ssrf_webhook_url_fetch",
    "name": "attacker-controlled webhook or callback URL fetch"
  },
  "structural_sanity": {
    "assigned_case_count": 22,
    "cwe_majority": "unspecified",
    "cwe_purity": 1.0,
    "flags": [],
    "metadata_cve_count": 22,
    "primary_hcvr_majority": "ssrf",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 58
  }
}