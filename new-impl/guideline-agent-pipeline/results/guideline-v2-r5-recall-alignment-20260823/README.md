# Guideline Recall Alignment

This report joins guideline-group diagnostics with recall ranks. It is for deciding whether a bad case is more likely a guideline-quality issue or an embedding/candidate-recall issue.

It does not generate guidelines, change ranking, call an LLM, or add fallback rules.

## Summary

- Recall table: `new-impl/guideline-agent-pipeline/results/p3c64-fixed143-paper-eval-20260820/p3c64_case_rank_table.jsonl`
- Recall label: `p3c64-current-guideline-baseline-control`
- Baseline label: `qwen3-embedding-4b`
- Same identity baseline: True
- Assigned cases: 185
- Joined recall cases: 30 / 143
- Guideline groups: 202
- Groups with assignments: 68
- Primary budget: Top-100
- Attention counts: {'embedding_or_candidate_recall_attention': 26, 'guideline_pending_review': 89, 'guideline_quality_attention': 167, 'missing_recall_rows': 53, 'recall_gain_evidence': 6, 'recall_regression_attention': 3}

## Highest Priority Groups

| Guideline | Mechanism | Cases | Hit@Primary | Flags | Attention | Example Misses |
| --- | --- | ---: | ---: | --- | --- | --- |
| `gl_mech_0188` | `mech_request_body_resource_mismatch_authz` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,recall_regression_attention | apolloconfig__apollo::CVE-2024-43397 |
| `gl_mech_0010` | `mech_template_expression_untrusted_eval` | 9 | 0/9 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | ballcat_projects__ballcat_codegen::CVE-2022-24881, baomidou__dynamic-datasource::CVE-2026-7045, browserup__browserup-proxy::CVE-2020-26282 |
| `gl_mech_0024` | `mech_ssrf_webhook_url_fetch` | 9 | 0/9 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | cbioportal__cbioportal::CVE-2024-41668, cc-tweaked__cc-tweaked::CVE-2023-37262, dhis2__dhis2-core::CVE-2022-41949 |
| `gl_mech_0021` | `mech_open_redirect_unsafe_uri_scheme` | 7 | 0/7 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | atjiu__pybbs::CVE-2025-8813, dspace__dspace::CVE-2022-31193, hs-web__hsweb-framework::CVE-2026-11477 |
| `gl_mech_0127` | `mech_missing_authentication_before_privileged_action` | 3 | 0/3 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | enonic__xp::CVE-2024-23679, metersphere__metersphere::CVE-2025-62604, webauthn4j__webauthn4j-spring-security::CVE-2023-45669 |
| `gl_mech_0186` | `mech_missing_authentication_before_privileged_action` | 2 | 0/2 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | jeecgboot__jeecgboot::CVE-2026-5616, theonedev__onedev::CVE-2021-21246 |
| `gl_mech_0001` | `mech_deserialization_untrusted_type_graph` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | archimatetool__archi::CVE-2023-40235 |
| `gl_mech_0008` | `mech_bean_property_reflection_escape` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | hubspot__jinjava::CVE-2025-59340 |
| `gl_mech_0009` | `mech_object_owner_scope_missing_authz` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | hubspot__jinjava::CVE-2026-25526 |
| `gl_mech_0012` | `mech_missing_authentication_before_privileged_action` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | feiyuchuixue__sz-boot-parent::CVE-2026-3189 |
| `gl_mech_0022` | `mech_path_traversal_missing_canonical_prefix` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | snowflakedb__snowflake-jdbc::CVE-2025-24789 |
| `gl_mech_0025` | `mech_missing_authentication_before_privileged_action` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | theonedev__onedev::CVE-2022-39205 |
| `gl_mech_0032` | `mech_deserialization_untrusted_type_graph` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | 4ra1n__super-xray::CVE-2022-41958 |
| `gl_mech_0051` | `mech_open_redirect_unsafe_uri_scheme` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | dataease__dataease::CVE-2025-64163 |
| `gl_mech_0076` | `mech_missing_authentication_before_privileged_action` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | openidentityplatform__opendj::CVE-2025-27497 |
| `gl_mech_0081` | `mech_path_traversal_missing_canonical_prefix` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | owasp__json-sanitizer::CVE-2021-23900 |
| `gl_mech_0097` | `mech_ssrf_webhook_url_fetch` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | micronaut-projects__micronaut-core::CVE-2020-7611 |
| `gl_mech_0110` | `mech_request_body_resource_mismatch_authz` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | arm32x__command-block-ide::CVE-2024-48645 |
| `gl_mech_0140` | `mech_bean_property_reflection_escape` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | indeedeng__util::CVE-2020-36634 |
| `gl_mech_0141` | `mech_missing_authentication_before_privileged_action` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | dspace__dspace::CVE-2022-31192 |
| `gl_mech_0143` | `mech_ssrf_webhook_url_fetch` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | mapfish__mapfish-print::CVE-2020-15231 |
| `gl_mech_0166` | `mech_template_expression_untrusted_eval` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | kiegroup__jbpm-wb::CVE-2013-6465 |
| `gl_mech_0169` | `mech_xml_external_entity_resolution` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | alkacon__opencms-core::CVE-2023-31544 |
| `gl_mech_0177` | `mech_privileged_server_side_capability_exposed` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention | xwiki__xwiki_platform::CVE-2022-23621 |
| `gl_mech_0190` | `mech_object_owner_scope_missing_authz` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention,missing_recall_rows | erudika__para::CVE-2022-1848 |

## Interpretation

- If a guideline is clean enough but recall misses many assigned cases, inspect embedding behavior, candidate slicing, or query wording before changing the taxonomy.
- If a guideline is mixed, pending, or lacks actionability fields, fix the guideline evidence and mechanism boundary before attributing failure to the embedding model.
- If a baseline is provided and `same_identity_baseline` is false, treat deltas as debugging context only.
