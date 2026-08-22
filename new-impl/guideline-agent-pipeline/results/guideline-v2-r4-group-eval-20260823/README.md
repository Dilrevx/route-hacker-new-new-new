# Guideline Group Evaluation

This report evaluates the offline guideline grouping itself. It does not use embedding scores, recall ranks, or known anchor locations.

## Summary

- Guidelines: 202
- Evaluated groups with case metadata: 68
- Source-only groups without case metadata: 134
- Assigned unique cases: 185 / 666
- Case coverage rate: 0.2777777777777778
- Pending candidate rows: 89
- Small groups: 43
- Mixed HCVR groups: 9
- Mixed CWE groups: 10
- Weighted HCVR purity: 0.7568
- Weighted CWE purity: 0.8676

## Interpretation

Use this report as the classification-side gate for guideline releases. A release can have clean mechanism groups but still perform poorly with a particular embedding model, and a release can improve recall while exposing overly broad or mixed guideline groups.
HCVR/CWE purity is computed only for groups that can be joined to unified case metadata; source-only historical CVE groups are reported separately instead of being treated as impure.
The structural labels are a sanity check, not the final definition of a good guideline. Mechanism quality should also be reviewed with human or LLM judging over the grouped CVE evidence.

## Flagged Groups

- `gl_mech_0013` `mech_path_traversal_missing_canonical_prefix`: cases=21, source_cves=82, flags=mixed_hcvr, HCVR=path_archive_traversal:0.57, CWE=unspecified:0.95
- `gl_mech_0007` `mech_path_traversal_missing_canonical_prefix`: cases=19, source_cves=45, flags=mixed_hcvr, HCVR=iris:0.42, CWE=unspecified:0.79
- `gl_mech_0002` `mech_xml_external_entity_resolution`: cases=11, source_cves=64, flags=mixed_hcvr,mixed_cwe, HCVR=unspecified:0.55, CWE=CWE-611:0.45
- `gl_mech_0129` `mech_missing_authentication_before_privileged_action`: cases=9, source_cves=15, flags=mixed_hcvr,mixed_cwe, HCVR=authentication_session_token_validation:0.67, CWE=unspecified:0.56
- `gl_mech_0005` `mech_temp_file_delete_mkdir_race`: cases=8, source_cves=12, flags=mixed_hcvr, HCVR=file_permission_temp_resource:0.50, CWE=unspecified:1.00
- `gl_mech_0047` `mech_deserialization_untrusted_type_graph`: cases=3, source_cves=18, flags=mixed_hcvr,mixed_cwe, HCVR=iris:0.67, CWE=unspecified:0.67
- `gl_mech_0068` `pending_mech_cluster_13_direct_string_concatenation_into_sql_query`: cases=3, source_cves=12, flags=pending_review, HCVR=unspecified:1.00, CWE=CWE-89:1.00
- `gl_mech_0073` `pending_mech_cluster_14_sql_injection_mitigated_by_input_escaping`: cases=3, source_cves=4, flags=pending_review, HCVR=unspecified:1.00, CWE=CWE-89:1.00
- `gl_mech_0082` `mech_privileged_server_side_capability_exposed`: cases=3, source_cves=3, flags=mixed_cwe, HCVR=iris:1.00, CWE=unspecified:0.67
- `gl_mech_0087` `pending_mech_cluster_16_missing_context_dependent_output_encoding`: cases=3, source_cves=5, flags=mixed_hcvr,mixed_cwe,pending_review, HCVR=unspecified:0.67, CWE=CWE-74:0.33
- `gl_mech_0118` `mech_toctou_mutable_object_reuse`: cases=3, source_cves=8, flags=mixed_cwe, HCVR=unspecified:1.00, CWE=CWE-400:0.50
- `gl_mech_0006` `pending_mech_cluster_1_insecure_default_permissions_on_temporary_files_created_with_file_crea`: cases=2, source_cves=2, flags=pending_review, HCVR=file_permission_temp_resource:1.00, CWE=unspecified:1.00
- `gl_mech_0017` `pending_mech_cluster_4_missing_allow_list_for_inline_content_disposition_leading_to_xss`: cases=2, source_cves=3, flags=pending_review, HCVR=iris:1.00, CWE=unspecified:1.00
- `gl_mech_0050` `mech_jndi_untrusted_lookup_target`: cases=2, source_cves=12, flags=mixed_hcvr, HCVR=iris:0.50, CWE=unspecified:1.00
- `gl_mech_0075` `mech_jndi_untrusted_lookup_target`: cases=2, source_cves=3, flags=mixed_hcvr,mixed_cwe, HCVR=authentication_session_token_validation:0.50, CWE=CWE-287:0.50
- `gl_mech_0084` `pending_mech_cluster_16_incomplete_dom_node_handling_in_sanitization`: cases=2, source_cves=2, flags=pending_review, HCVR=iris:1.00, CWE=unspecified:1.00
- `gl_mech_0132` `pending_mech_cluster_23_missing_cryptographic_token_verification`: cases=2, source_cves=3, flags=mixed_cwe,pending_review, HCVR=authentication_session_token_validation:1.00, CWE=CWE-290:0.50
- `gl_mech_0001` `mech_deserialization_untrusted_type_graph`: cases=1, source_cves=6, flags=small_group, HCVR=information_disclosure:1.00, CWE=unspecified:1.00
- `gl_mech_0008` `mech_bean_property_reflection_escape`: cases=1, source_cves=1, flags=small_group, HCVR=template_expression_injection:1.00, CWE=unspecified:1.00
- `gl_mech_0009` `mech_object_owner_scope_missing_authz`: cases=1, source_cves=1, flags=small_group, HCVR=template_expression_injection:1.00, CWE=unspecified:1.00
