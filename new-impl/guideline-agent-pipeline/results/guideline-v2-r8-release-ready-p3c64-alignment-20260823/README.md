# Guideline Recall Alignment

This report joins guideline-group diagnostics with recall ranks. It is for deciding whether a bad case is more likely a guideline-quality issue or an embedding/candidate-recall issue.

It does not generate guidelines, change ranking, call an LLM, or add fallback rules.

## Summary

- Recall table: `new-impl/guideline-agent-pipeline/results/guideline-v2-r7-full143-p3c64-20260823/r7_case_rank_table.jsonl`
- Recall label: `r7-p3c64-full143`
- Baseline label: `none`
- Same identity baseline: True
- Assigned cases: 189
- Joined recall cases: 28 / 143
- Guideline groups: 177
- Groups with assignments: 56
- Primary budget: Top-100
- Attention counts: {'embedding_or_candidate_recall_attention': 44, 'guideline_quality_attention': 121, 'label_mixed_structural_attention': 8, 'missing_recall_rows': 44}
- Blocking guideline flags: ['incomplete_actionability_fields', 'pending_review', 'review_only', 'source_only_no_case_metadata']
- Label-mixed flags are blocking: False

## Highest Priority Groups

| Guideline | Mechanism | Cases | Hit@Primary | Flags | Attention | Example Misses |
| --- | --- | ---: | ---: | --- | --- | --- |
| `gl_mech_0117` | `mech_ssrf_webhook_url_fetch` | 22 | 0/22 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | backstage__backstage::CVE-2026-32236, bergskenop__blender-mcp::CVE-2026-10662, budibase__budibase::CVE-2026-31818 |
| `gl_mech_0005` | `mech_path_traversal_missing_canonical_prefix` | 18 | 0/18 (0.00) | mixed_hcvr | label_mixed_structural_attention,embedding_or_candidate_recall_attention,missing_recall_rows | 94fzb__zrlog-plugin-backup-sql-file::CVE-2024-57669, apache__jclouds::CVE-2025-24961, dspace__dspace::CVE-2022-31194 |
| `gl_mech_0022` | `mech_xml_external_entity_resolution` | 13 | 0/13 (0.00) | mixed_hcvr,mixed_cwe | label_mixed_structural_attention,embedding_or_candidate_recall_attention,missing_recall_rows | allure-framework__allure2::CVE-2025-52888, apache__cxf-fediz::CVE-2018-8038, archimatetool__archi::CVE-2023-40235 |
| `gl_mech_0040` | `mech_template_expression_untrusted_eval` | 10 | 0/10 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | ballcat_projects__ballcat_codegen::CVE-2022-24881, browserup__browserup-proxy::CVE-2020-26282, codecentric__spring-boot-admin::CVE-2022-46166 |
| `gl_mech_0001` | `mech_temp_file_delete_mkdir_race` | 8 | 0/8 (0.00) | mixed_hcvr | label_mixed_structural_attention,embedding_or_candidate_recall_attention,missing_recall_rows | centic9__jgit-cookbook::CVE-2022-4817, devent__globalpom-utils::CVE-2018-25068, fusesource__hawtjni::CVE-2013-2035 |
| `gl_mech_0060` | `mech_sql_dynamic_query_untrusted_fragment` | 5 | 0/5 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | dashbuilder__dashbuilder::CVE-2016-4999, dhis2__dhis2-core::CVE-2022-24848, kyuubl__school-register::CVE-2015-10047 |
| `gl_mech_0092` | `mech_html_sanitizer_policy_gap` | 4 | 0/4 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | hibernate__hibernate-validator::CVE-2019-10219, nahsra__antisamy::CVE-2022-28367, nahsra__antisamy::CVE-2022-29577 |
| `gl_mech_0114` | `mech_open_redirect_unsafe_uri_scheme` | 3 | 0/3 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | ethereum__web3.py::CVE-2026-40072, sorlen008__desktopcommandermcp::CVE-2026-10690, weblateorg__weblate::CVE-2026-33440 |
| `gl_mech_0003` | `mech_inline_content_disposition_xss` | 2 | 0/2 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | cuba-platform__jpawebapi::CVE-2025-32961, cuba-platform__restapi::CVE-2025-32960 |
| `gl_mech_0093` | `mech_binary_length_unbounded_resource_use` | 2 | 0/2 (0.00) | mixed_cwe | label_mixed_structural_attention,embedding_or_candidate_recall_attention,missing_recall_rows | fasterxml__jackson-dataformats-binary::CVE-2020-28491, xerial__snappy-java::CVE-2023-34455 |
| `gl_mech_0105` | `mech_state_precondition_missing_before_effect` | 2 | 0/2 (0.00) |  | embedding_or_candidate_recall_attention | eclipse-californium__californium::CVE-2022-39368, netty__netty::CVE-2026-42577 |
| `gl_mech_0164` | `mech_authentication_artifact_incomplete_validation` | 2 | 0/2 (0.00) | mixed_hcvr,mixed_cwe | label_mixed_structural_attention,embedding_or_candidate_recall_attention,missing_recall_rows | micronaut-projects__micronaut-security::CVE-2023-36820, openstack__keystone::CVE-2012-5571 |
| `gl_mech_0170` | `mech_object_owner_scope_missing_authz` | 2 | 0/2 (0.00) | mixed_cwe | label_mixed_structural_attention,embedding_or_candidate_recall_attention,missing_recall_rows | dspace__dspace::CVE-2021-41189, jeecgboot__jeecgboot::CVE-2025-14908 |
| `gl_mech_0171` | `mech_request_body_resource_mismatch_authz` | 2 | 0/2 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | apolloconfig__apollo::CVE-2024-43397, theonedev__onedev::CVE-2021-21246 |
| `gl_mech_0004` | `mech_object_owner_scope_missing_authz` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | jenkinsci__jenkins::CVE-2017-2599 |
| `gl_mech_0007` | `mech_ssrf_webhook_url_fetch` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | feiyuchuixue__sz-boot-parent::CVE-2026-3189 |
| `gl_mech_0010` | `mech_archive_symlink_extraction_escape` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | codehaus-plexus__plexus-archiver::CVE-2023-37460 |
| `gl_mech_0015` | `mech_temp_file_delete_mkdir_race` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | psf__requests::CVE-2026-25645 |
| `gl_mech_0028` | `mech_request_body_resource_mismatch_authz` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | openclaw__openclaw::CVE-2026-40037 |
| `gl_mech_0030` | `mech_ssrf_webhook_url_fetch` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | openclaw__openclaw::CVE-2026-41913 |
| `gl_mech_0045` | `mech_ldap_filter_unescaped_input` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | gocd__gocd-ldap-authentication-plugin::CVE-2022-24832 |
| `gl_mech_0046` | `mech_jndi_untrusted_lookup_target` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention | apache__axis-axis1-java::CVE-2023-51441 |
| `gl_mech_0048` | `mech_jndi_untrusted_lookup_target` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | dataease__dataease::CVE-2025-58045 |
| `gl_mech_0050` | `mech_ssrf_webhook_url_fetch` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | dataease__dataease::CVE-2025-64163 |
| `gl_mech_0051` | `mech_template_expression_untrusted_eval` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | baomidou__dynamic-datasource::CVE-2026-7045 |

## Interpretation

- If a guideline is clean enough but recall misses many assigned cases, inspect embedding behavior, candidate slicing, or query wording before changing the taxonomy.
- If a guideline is pending, review-only, source-only, or lacks actionability fields, fix the guideline evidence and mechanism boundary before attributing failure to the embedding model.
- If a guideline only has mixed HCVR/CWE structural labels, review the examples but do not treat label purity as a hard gate; reusable mechanisms can cut across public CWE or dataset labels.
- If a baseline is provided and `same_identity_baseline` is false, treat deltas as debugging context only.
