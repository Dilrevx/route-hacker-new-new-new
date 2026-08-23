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
- Attention counts: {'embedding_or_candidate_recall_attention': 6, 'guideline_quality_attention': 121, 'label_mixed_structural_attention': 8, 'missing_recall_rows': 44}
- Blocking guideline flags: ['incomplete_actionability_fields', 'pending_review', 'review_only', 'source_only_no_case_metadata']
- Label-mixed flags are blocking: False

## Highest Priority Groups

| Guideline | Mechanism | Cases | Hit@Primary | Flags | Attention | Example Misses |
| --- | --- | ---: | ---: | --- | --- | --- |
| `gl_mech_0001` | `mech_temp_file_delete_mkdir_race` | 8 | 0/8 (0.00) | mixed_hcvr | label_mixed_structural_attention,embedding_or_candidate_recall_attention,missing_recall_rows | centic9__jgit-cookbook::CVE-2022-4817, devent__globalpom-utils::CVE-2018-25068, fusesource__hawtjni::CVE-2013-2035 |
| `gl_mech_0170` | `mech_object_owner_scope_missing_authz` | 2 | 0/2 (0.00) | mixed_cwe | label_mixed_structural_attention,embedding_or_candidate_recall_attention,missing_recall_rows | dspace__dspace::CVE-2021-41189, jeecgboot__jeecgboot::CVE-2025-14908 |
| `gl_mech_0171` | `mech_request_body_resource_mismatch_authz` | 2 | 0/2 (0.00) |  | embedding_or_candidate_recall_attention,missing_recall_rows | apolloconfig__apollo::CVE-2024-43397, theonedev__onedev::CVE-2021-21246 |
| `gl_mech_0046` | `mech_jndi_untrusted_lookup_target` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention | apache__axis-axis1-java::CVE-2023-51441 |
| `gl_mech_0118` | `mech_toctou_mutable_object_reuse` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention | okta__okta-sdk-java::CVE-2025-66033 |
| `gl_mech_0172` | `mech_sql_dynamic_query_untrusted_fragment` | 1 | 0/1 (0.00) | small_group | embedding_or_candidate_recall_attention | steve-community__steve::CVE-2026-28230 |
| `gl_mech_0006` | `mech_request_body_resource_mismatch_authz` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0008` | `mech_temp_file_delete_mkdir_race` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0009` | `mech_template_expression_untrusted_eval` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0012` | `mech_html_sanitizer_policy_gap` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0013` | `mech_archive_symlink_extraction_escape` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0014` | `mech_path_traversal_missing_canonical_prefix` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0016` | `mech_path_traversal_missing_canonical_prefix` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0017` | `mech_deserialization_untrusted_type_graph` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0018` | `mech_binary_length_unbounded_resource_use` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0019` | `mech_html_sanitizer_policy_gap` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0020` | `mech_xml_external_entity_resolution` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0021` | `mech_template_expression_untrusted_eval` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0023` | `mech_bean_property_reflection_escape` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0024` | `mech_ssrf_webhook_url_fetch` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0026` | `mech_ssrf_webhook_url_fetch` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0029` | `mech_ssrf_redirect_following_client` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0031` | `mech_state_precondition_missing_before_effect` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0032` | `mech_deserialization_untrusted_type_graph` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |
| `gl_mech_0033` | `mech_jndi_untrusted_lookup_target` | 0 | n/a | source_only_no_case_metadata | guideline_quality_attention |  |

## Interpretation

- If a guideline is clean enough but recall misses many assigned cases, inspect embedding behavior, candidate slicing, or query wording before changing the taxonomy.
- If a guideline is pending, review-only, source-only, or lacks actionability fields, fix the guideline evidence and mechanism boundary before attributing failure to the embedding model.
- If a guideline only has mixed HCVR/CWE structural labels, review the examples but do not treat label purity as a hard gate; reusable mechanisms can cut across public CWE or dataset labels.
- If a baseline is provided and `same_identity_baseline` is false, treat deltas as debugging context only.
