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
          "end_line": 262,
          "file": "core/src/main/java/hudson/model/AbstractItem.java",
          "span_kind": "phase21_008_review_entry_window",
          "start_line": 236,
          "symbol": "AbstractItem.renameTo"
        },
        {
          "end_line": 339,
          "file": "core/src/main/java/hudson/model/ItemGroupMixIn.java",
          "span_kind": "method",
          "start_line": 314,
          "symbol": "createProject"
        },
        {
          "end_line": 334,
          "file": "core/src/main/java/hudson/model/ItemGroupMixIn.java",
          "span_kind": "method",
          "start_line": 311,
          "symbol": "createProject"
        },
        {
          "end_line": 463,
          "file": "core/src/main/java/hudson/model/Items.java",
          "span_kind": "method",
          "start_line": 445,
          "symbol": "verifyItemDoesNotAlreadyExist"
        }
      ],
      "case_id": "case::dedac3efeb3350ec76a8",
      "cve_ids": [
        "CVE-2017-2599"
      ],
      "cwe_ids": [
        "CWE-863"
      ],
      "identity_key": "jenkinsci__jenkins::CVE-2017-2599",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "创建或重命名项目时没有充分检查目标名称是否已被其他不可见项目占用，可能导致已存在项目被新建项目覆盖，有风险。原代码标注了此条TODO，在这个patch中被修复 ``` if (parent.getItem(name) != null) { throw new IllegalArgumentException(parent.getDisplayName() + \" already contains an item '\" + name + \"'\"); } // TODO what if we have no DISCOVER permission on the existing job? // VULNERABILITY: 仅检查当前用户可见的项目，攻击者可用自己的项目覆盖不可见的同名项目 ``` 新增安全检查verifyItemDoesNotAlreadyExist ``` static void verifyItemDoesNotAlreadyExist(@Nonnull ItemGroup<?> parent, @Nonnull String newName, @CheckFo...",
        "Phase 21.008 materialized this label only after taking a Phase 21.007 source-acquisition work order, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": "Jenkins before versions 2.44 and 2.32.2 is vulnerable to an insufficient permission check. This allows users with permissions to create new items (e.g. jobs) to overwrite existing items they don't have access to (SECURITY-321)."
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities where user-controlled input is used to construct file paths or resource identifiers without proper validation, canonicalization, or containment checks, enabling directory traversal, unauthorized file read/write, or resource access. A minority of outliers involve unrelated vulnerabilities like deserialization, SSRF, regular expression injection, and stored XSS.",
  "guideline_group_key": "cluster_0002__mech_object_owner_scope_missing_authz",
  "guideline_id": "gl_mech_0004",
  "guideline_text": "Trace attacker-selected resource identifiers, object IDs, tenant IDs, or administrative action targets into sensitive read, write, mutation, deletion, workflow, or administrative operations on the selected resource. Report code paths where the authorization decision is not bound to both the current principal and the exact resource or tenant being affected. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should check ownership or tenant scope before the effect and carry that checked identity into the data access or mutation.",
  "judge_selection_reason": "small_group",
  "mechanism": {
    "family": "authorization",
    "mechanism_id": "mech_object_owner_scope_missing_authz",
    "name": "missing object-owner or tenant-scope authorization"
  },
  "structural_sanity": {
    "assigned_case_count": 1,
    "cwe_majority": "CWE-863",
    "cwe_purity": 1.0,
    "flags": [
      "small_group"
    ],
    "metadata_cve_count": 1,
    "primary_hcvr_majority": "authorization_bypass",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 1
  }
}