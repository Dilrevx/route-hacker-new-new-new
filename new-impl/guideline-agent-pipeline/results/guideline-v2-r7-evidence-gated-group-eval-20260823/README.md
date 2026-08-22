# Guideline Group Evaluation

This report evaluates the offline guideline grouping itself. It does not use embedding scores, recall ranks, or known anchor locations.

## Summary

- Guidelines: 563
- Evaluated groups with case metadata: 119
- Source-only groups without case metadata: 444
- Assigned unique cases: 276 / 666
- Case coverage rate: 0.4144144144144144
- Pending candidate rows: 386
- Small groups: 87
- Mixed HCVR groups: 8
- Mixed CWE groups: 8
- Weighted HCVR purity: 0.8659
- Weighted CWE purity: 0.9245

## Interpretation

Use this report as a diagnostic triage view for guideline releases, not as a hard pass/fail gate. A release can have clean mechanism groups but still perform poorly with a particular embedding model, and a release can improve recall while exposing overly broad or mixed guideline groups.
HCVR/CWE purity is computed only for groups that can be joined to unified case metadata; source-only historical CVE groups are reported separately instead of being treated as impure.
The structural labels are weak triage signals, not optimization targets and not the final definition of a good guideline. Mechanism quality should also be reviewed with human or LLM judging over the grouped CVE evidence, and final paper claims still require same-identity embedding recall.

## Flagged Groups

- `gl_mech_0009` `mech_path_traversal_missing_canonical_prefix`: cases=18, source_cves=48, flags=mixed_hcvr, HCVR=path_archive_traversal:0.61, CWE=unspecified:0.94
- `gl_mech_0026` `mech_path_traversal_missing_canonical_prefix`: cases=14, source_cves=38, flags=mixed_hcvr, HCVR=iris:0.50, CWE=unspecified:0.71
- `gl_mech_0047` `mech_xml_external_entity_resolution`: cases=13, source_cves=66, flags=mixed_hcvr,mixed_cwe, HCVR=unspecified:0.46, CWE=unspecified:0.54
- `gl_mech_0001` `mech_temp_file_delete_mkdir_race`: cases=8, source_cves=10, flags=mixed_hcvr, HCVR=toctou_check_use_race:0.62, CWE=unspecified:1.00
- `gl_mech_0514` `pending_mech_cluster_89_missing_validation_in_authentication_authorization_flows`: cases=7, source_cves=11, flags=mixed_hcvr,pending_review, HCVR=authentication_session_token_validation:0.57, CWE=unspecified:0.71
- `gl_mech_0017` `pending_mech_cluster_2_missing_or_insufficient_path_validation_for_file_and_resource_access`: cases=5, source_cves=30, flags=mixed_hcvr,pending_review, HCVR=path_archive_traversal:0.60, CWE=unspecified:1.00
- `gl_mech_0509` `pending_mech_cluster_89_authentication_bypass_and_token_validation_flaws`: cases=4, source_cves=8, flags=pending_review, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `gl_mech_0513` `pending_mech_cluster_89_jwt_signature_verification_and_algorithm_handling_failures`: cases=4, source_cves=7, flags=pending_review, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:0.75
- `gl_mech_0003` `pending_mech_cluster_1_incomplete_handling_of_bundle_item_interactions_in_inventory`: cases=3, source_cves=3, flags=pending_review, HCVR=business_state_precondition:1.00, CWE=unspecified:1.00
- `gl_mech_0079` `mech_deserialization_untrusted_type_graph`: cases=3, source_cves=15, flags=mixed_hcvr,mixed_cwe, HCVR=iris:0.67, CWE=unspecified:0.67
- `gl_mech_0133` `pending_mech_cluster_23_replace_backtracking_regex_engine_with_linear_time_alternative`: cases=2, source_cves=3, flags=pending_review, HCVR=iris:1.00, CWE=unspecified:1.00
- `gl_mech_0137` `pending_mech_cluster_25_information_leakage_due_to_missing_redaction`: cases=2, source_cves=5, flags=pending_review, HCVR=iris:1.00, CWE=unspecified:1.00
- `gl_mech_0229` `pending_mech_cluster_41_crlf_injection_due_to_missing_header_value_validation`: cases=2, source_cves=15, flags=mixed_cwe,pending_review, HCVR=unspecified:1.00, CWE=CWE-444:0.67
- `gl_mech_0265` `pending_mech_cluster_46_missing_validation_of_cryptographic_parameters_and_keys`: cases=2, source_cves=7, flags=pending_review, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `gl_mech_0302` `mech_binary_length_unbounded_resource_use`: cases=2, source_cves=12, flags=mixed_cwe, HCVR=unspecified:1.00, CWE=CWE-770:0.67
- `gl_mech_0331` `pending_mech_cluster_60_missing_restrictive_file_permissions_on_sensitive_files`: cases=2, source_cves=2, flags=pending_review, HCVR=file_permission_temp_resource:1.00, CWE=unspecified:1.00
- `gl_mech_0406` `pending_mech_cluster_74_authentication_bypass_via_untrusted_headers_or_loopback_trust`: cases=2, source_cves=2, flags=mixed_cwe,pending_review, HCVR=authentication_session_token_validation:1.00, CWE=CWE-287:0.50
- `gl_mech_0507` `mech_authentication_artifact_incomplete_validation`: cases=2, source_cves=3, flags=mixed_hcvr,mixed_cwe, HCVR=authentication_session_token_validation:0.50, CWE=CWE-255:0.50
- `gl_mech_0534` `mech_object_owner_scope_missing_authz`: cases=2, source_cves=6, flags=mixed_cwe, HCVR=authorization_bypass:1.00, CWE=CWE-863:0.50
- `gl_mech_0004` `pending_mech_cluster_1_missing_access_control_for_slot_modifications`: cases=1, source_cves=1, flags=small_group,pending_review, HCVR=business_state_precondition:1.00, CWE=unspecified:1.00
