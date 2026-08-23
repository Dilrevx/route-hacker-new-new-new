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
          "end_line": 749,
          "file": "dspace-api/src/main/java/org/dspace/eperson/GroupServiceImpl.java",
          "span_kind": "phase21_013_review_entry_window",
          "start_line": 735,
          "symbol": "GroupServiceImpl.getParentObject"
        },
        {
          "end_line": 103,
          "file": "dspace-server-webapp/src/main/java/org/dspace/app/rest/GroupRestController.java",
          "span_kind": "method",
          "start_line": 72,
          "symbol": "addChildGroups"
        },
        {
          "end_line": 613,
          "file": "dspace-api/src/main/java/org/dspace/app/util/AuthorizeUtil.java",
          "span_kind": "method",
          "start_line": 566,
          "symbol": "authorizeManageGroup"
        },
        {
          "end_line": 757,
          "file": "dspace-api/src/main/java/org/dspace/eperson/GroupServiceImpl.java",
          "span_kind": "method",
          "start_line": 676,
          "symbol": "getParentObject"
        },
        {
          "end_line": 769,
          "file": "dspace-api/src/main/java/org/dspace/eperson/GroupServiceImpl.java",
          "span_kind": "method",
          "start_line": 677,
          "symbol": "getParentObject"
        }
      ],
      "case_id": "case::0fe8e1fed6ec861f1ebc",
      "cve_ids": [
        "CVE-2021-41189"
      ],
      "cwe_ids": [
        "CWE-863"
      ],
      "identity_key": "dspace__dspace::CVE-2021-41189",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "GroupServiceImpl.java文件中getParentObject函数直接返回策略列表中的第一个策略，没有匹配当前用户组名称与策略的默认读取组名，可能造成提权 原代码 ''' if (policies.size() > 0) { return policies.get(0).getdSpaceObject(); } policies = resourcePolicyService.find(context, null, groups, Constants.DEFAULT_BITSTREAM_READ, Constants.COLLECTION); if (policies.size() > 0) { return policies.get(0).getdSpaceObject(); ''' 修改后代码 ''' Optional<ResourcePolicy> defaultPolicy = policies.stream().filter(p -> StringUtils.equals( collectionService.getDefaultReadGroupNam...",
        "Phase 21.013 materialized this label only after selecting a Phase 21.006 ranked patch-backed backlog row, resolving the public patch commit to its parent pre-patch source tree, and verifying a compact source span against expected old-side patch tokens. The label is review-entry retrieval ground truth, not exploit proof."
      ],
      "vulnerability_description": "DSpace is an open source turnkey repository application. In version 7.0, any community or collection administrator can escalate their permission up to become system administrator. This vulnerability only exists in 7.0 and does not impact 6.x or below. This issue is patched in version 7.1. As a workaround, users of 7.0 may temporarily disable the ability for community or collection administrators to manage permissions or workflows settings."
    },
    {
      "anchor_examples": [
        {
          "end_line": 529,
          "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysTenantController.java",
          "span_kind": "phase21_066_review_entry_window",
          "start_line": 510,
          "symbol": "SysTenantController.joinTenantByHouseNumber"
        },
        {
          "end_line": 950,
          "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysTenantController.java",
          "span_kind": "phase21_066_review_entry_window",
          "start_line": 914,
          "symbol": "SysTenantController.agreeOrRefuseJoinTenant"
        },
        {
          "end_line": 718,
          "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysTenantController.java",
          "span_kind": "phase21_066_review_entry_window",
          "start_line": 709,
          "symbol": "SysTenantController.invitationUser"
        },
        {
          "end_line": 520,
          "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysTenantController.java",
          "span_kind": "file_region",
          "start_line": 518,
          "symbol": "SysTenantController.joinTenantByHouseNumber.center_window_3"
        },
        {
          "end_line": 521,
          "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysTenantController.java",
          "span_kind": "file_region",
          "start_line": 517,
          "symbol": "SysTenantController.joinTenantByHouseNumber.center_window_5"
        }
      ],
      "case_id": "case::459021bb844696d07d1f",
      "cve_ids": [
        "CVE-2025-14908"
      ],
      "cwe_ids": [
        "unspecified"
      ],
      "identity_key": "jeecgboot__jeecgboot::CVE-2025-14908",
      "primary_hcvr_type": "authorization_bypass",
      "trace_evidence": [
        "This compact label covers a tenant-management HTTP handler that executes a sensitive tenant membership or invitation action without a method-level permission gate. The patch either removes the exposed handler by commenting it out or adds the missing permission annotation."
      ],
      "vulnerability_description": ""
    }
  ],
  "cluster_summary": "This cluster comprises vulnerabilities where the application fails to enforce proper access control, including missing authentication on endpoints (allowing unauthenticated access), missing resource-scoped authorization (IDOR) where user-supplied identifiers are not verified, missing permission annotations on controller methods, and logic errors in authorization conditions. These flaws enable unauthorized access to sensitive data or privileged operations.",
  "guideline_group_key": "cluster_0093__mech_object_owner_scope_missing_authz",
  "guideline_id": "gl_mech_0534",
  "guideline_text": "Trace attacker-selected resource identifiers, object IDs, tenant IDs, or administrative action targets into sensitive read, write, mutation, deletion, workflow, or administrative operations on the selected resource. Report code paths where the authorization decision is not bound to both the current principal and the exact resource or tenant being affected. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should check ownership or tenant scope before the effect and carry that checked identity into the data access or mutation.",
  "mechanism": {
    "family": "authorization",
    "mechanism_id": "mech_object_owner_scope_missing_authz",
    "name": "missing object-owner or tenant-scope authorization"
  },
  "structural_sanity": {
    "assigned_case_count": 2,
    "cwe_majority": "CWE-863",
    "cwe_purity": 0.5,
    "flags": [
      "mixed_cwe"
    ],
    "metadata_cve_count": 2,
    "primary_hcvr_majority": "authorization_bypass",
    "primary_hcvr_purity": 1.0,
    "source_cve_count": 6
  }
}