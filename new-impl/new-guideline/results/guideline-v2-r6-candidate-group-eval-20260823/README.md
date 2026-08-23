# Guideline Group Evaluation

This report evaluates the offline guideline grouping itself. It does not use embedding scores, recall ranks, or known anchor locations.

## Summary

- Guidelines: 433
- Evaluated groups with case metadata: 103
- Source-only groups without case metadata: 330
- Assigned unique cases: 276 / 666
- Case coverage rate: 0.4144144144144144
- Pending candidate rows: 148
- Small groups: 69
- Mixed HCVR groups: 10
- Mixed CWE groups: 7
- Weighted HCVR purity: 0.8297
- Weighted CWE purity: 0.9142

## Interpretation

Use this report as a diagnostic triage view for guideline releases, not as a hard pass/fail gate. A release can have clean mechanism groups but still perform poorly with a particular embedding model, and a release can improve recall while exposing overly broad or mixed guideline groups.
HCVR/CWE purity is computed only for groups that can be joined to unified case metadata; source-only historical CVE groups are reported separately instead of being treated as impure.
The structural labels are weak triage signals, not optimization targets and not the final definition of a good guideline. Mechanism quality should also be reviewed with human or LLM judging over the grouped CVE evidence, and final paper claims still require same-identity embedding recall.

## Flagged Groups

- `gl_mech_0012` `mech_path_traversal_missing_canonical_prefix`: cases=27, source_cves=89, flags=mixed_hcvr, HCVR=path_archive_traversal:0.52, CWE=unspecified:0.93
- `gl_mech_0021` `mech_path_traversal_missing_canonical_prefix`: cases=14, source_cves=40, flags=mixed_hcvr, HCVR=iris:0.50, CWE=unspecified:0.71
- `gl_mech_0036` `mech_xml_external_entity_resolution`: cases=14, source_cves=74, flags=mixed_hcvr,mixed_cwe, HCVR=unspecified:0.43, CWE=unspecified:0.57
- `gl_mech_0001` `mech_temp_file_delete_mkdir_race`: cases=7, source_cves=9, flags=mixed_hcvr, HCVR=toctou_check_use_race:0.57, CWE=unspecified:1.00
- `gl_mech_0062` `mech_deserialization_untrusted_type_graph`: cases=3, source_cves=22, flags=mixed_hcvr,mixed_cwe, HCVR=iris:0.67, CWE=unspecified:0.67
- `gl_mech_0004` `mech_object_owner_scope_missing_authz`: cases=2, source_cves=2, flags=mixed_hcvr, HCVR=authorization_bypass:0.50, CWE=unspecified:1.00
- `gl_mech_0006` `pending_mech_cluster_1_incomplete_handling_of_bundle_item_interactions_in_inventory`: cases=2, source_cves=2, flags=pending_review, HCVR=business_state_precondition:1.00, CWE=unspecified:1.00
- `gl_mech_0109` `pending_mech_cluster_23_replace_backtracking_regex_engine_with_linear_time_alternative`: cases=2, source_cves=3, flags=pending_review, HCVR=iris:1.00, CWE=unspecified:1.00
- `gl_mech_0110` `mech_ldap_filter_unescaped_input`: cases=2, source_cves=10, flags=mixed_hcvr,mixed_cwe, HCVR=iris:0.50, CWE=CWE-74:0.50
- `gl_mech_0112` `pending_mech_cluster_25_information_leakage_due_to_missing_redaction`: cases=2, source_cves=4, flags=pending_review, HCVR=iris:1.00, CWE=unspecified:1.00
- `gl_mech_0175` `mech_ssrf_redirect_following_client`: cases=2, source_cves=3, flags=mixed_hcvr, HCVR=open_redirect:0.50, CWE=unspecified:1.00
- `gl_mech_0255` `mech_binary_length_unbounded_resource_use`: cases=2, source_cves=13, flags=mixed_cwe, HCVR=unspecified:1.00, CWE=CWE-770:0.67
- `gl_mech_0278` `pending_mech_cluster_60_missing_restrictive_file_permissions_on_sensitive_files`: cases=2, source_cves=2, flags=pending_review, HCVR=file_permission_temp_resource:1.00, CWE=unspecified:1.00
- `gl_mech_0288` `mech_privileged_server_side_capability_exposed`: cases=2, source_cves=11, flags=mixed_hcvr, HCVR=authorization_bypass:0.50, CWE=unspecified:1.00
- `gl_mech_0337` `mech_missing_authentication_before_privileged_action`: cases=2, source_cves=15, flags=mixed_cwe, HCVR=authentication_session_token_validation:1.00, CWE=CWE-287:0.50
- `gl_mech_0363` `mech_object_owner_scope_missing_authz`: cases=2, source_cves=22, flags=mixed_hcvr, HCVR=authentication_session_token_validation:0.50, CWE=unspecified:1.00
- `gl_mech_0003` `mech_toctou_mutable_object_reuse`: cases=1, source_cves=1, flags=small_group, HCVR=toctou_check_use_race:1.00, CWE=unspecified:1.00
- `gl_mech_0005` `mech_toctou_mutable_object_reuse`: cases=1, source_cves=1, flags=small_group, HCVR=business_state_precondition:1.00, CWE=unspecified:1.00
- `gl_mech_0007` `pending_mech_cluster_1_missing_validation_of_fake_output_slots`: cases=1, source_cves=1, flags=small_group,pending_review, HCVR=business_state_precondition:1.00, CWE=unspecified:1.00
- `gl_mech_0008` `mech_html_sanitizer_policy_gap`: cases=1, source_cves=1, flags=small_group, HCVR=unspecified:1.00, CWE=CWE-79:1.00
