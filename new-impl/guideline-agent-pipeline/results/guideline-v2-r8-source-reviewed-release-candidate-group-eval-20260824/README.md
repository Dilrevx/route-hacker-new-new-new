# Guideline Group Evaluation

This report evaluates the offline guideline grouping itself. It does not use embedding scores, recall ranks, or known anchor locations.

## Summary

- Guidelines: 33
- Evaluated groups with case metadata: 28
- Source-only groups without case metadata: 5
- Assigned unique cases: 48 / 666
- Case coverage rate: 0.07207207207207207
- Pending candidate rows: 0
- Review queue included: False
- Small groups: 16
- Mixed HCVR groups: 2
- Mixed CWE groups: 2
- Weighted HCVR purity: 0.9375
- Weighted CWE purity: 0.9375

## Interpretation

Use this report as a diagnostic triage view for guideline releases, not as a hard pass/fail gate. A release can have clean mechanism groups but still perform poorly with a particular embedding model, and a release can improve recall while exposing overly broad or mixed guideline groups.
HCVR/CWE purity is computed only for groups that can be joined to unified case metadata; source-only historical CVE groups are reported separately instead of being treated as impure.
The structural labels are weak triage signals, not optimization targets and not the final definition of a good guideline. Mechanism quality should also be reviewed with human or LLM judging over the grouped CVE evidence, and final paper claims still require same-identity embedding recall.

## Flagged Groups

- `sr_mech_0011` `mech_xml_external_entity_resolution`: cases=4, source_cves=0, flags=mixed_hcvr,mixed_cwe, HCVR=unspecified:0.50, CWE=unspecified:0.50
- `sr_mech_0020` `mech_static_resource_path_traversal_missing_final_containment`: cases=2, source_cves=0, flags=mixed_hcvr, HCVR=iris:0.50, CWE=unspecified:1.00
- `sr_mech_0027` `mech_jjwt_parse_without_jws_signature_verification`: cases=2, source_cves=0, flags=mixed_cwe, HCVR=authentication_session_token_validation:1.00, CWE=CWE-290:0.50
- `sr_mech_0005` `mech_ssrf_untrusted_url_download_openstream`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=ssrf:1.00, CWE=unspecified:1.00
- `sr_mech_0010` `mech_predictable_archive_member_temp_path_check_write_race`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=toctou_check_use_race:1.00, CWE=unspecified:1.00
- `sr_mech_0012` `mech_untrusted_template_text_engine_exec`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=template_expression_injection:1.00, CWE=unspecified:1.00
- `sr_mech_0014` `mech_spel_unrestricted_evaluation_context`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=iris:1.00, CWE=unspecified:1.00
- `sr_mech_0021` `mech_multipart_original_filename_path_write`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=path_archive_traversal:1.00, CWE=unspecified:1.00
- `sr_mech_0022` `mech_recursive_copy_move_missing_ancestor_guard`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=path_archive_traversal:1.00, CWE=unspecified:1.00
- `sr_mech_0023` `mech_jwt_default_allows_none_algorithm`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `sr_mech_0024` `mech_empty_token_reaches_auth_callback`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `sr_mech_0025` `mech_public_default_jwt_secret_fallback`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `sr_mech_0026` `mech_oidc_server_session_not_bound_to_token_expiry`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `sr_mech_0028` `mech_jose_header_supplied_jwk_key_trust`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `sr_mech_0029` `mech_oidc_unsigned_id_token_default_allowed`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `sr_mech_0030` `mech_inactive_identifier_authentication_acceptance`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authentication_session_token_validation:1.00, CWE=CWE-287:1.00
- `sr_mech_0031` `mech_media_filter_missing_token_allows_controller_access`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authorization_bypass:1.00, CWE=unspecified:1.00
- `sr_mech_0032` `mech_token_presence_check_without_validation`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authentication_session_token_validation:1.00, CWE=unspecified:1.00
- `sr_mech_0033` `mech_empty_token_scope_satisfies_required_scope`: cases=1, source_cves=0, flags=small_group,review_only, HCVR=authorization_bypass:1.00, CWE=unspecified:1.00
- `sr_mech_0003` `mech_absolute_resource_path_traversal_missing_component_validation`: cases=0, source_cves=0, flags=source_only_no_case_metadata,review_only, HCVR=:0.00, CWE=:0.00
