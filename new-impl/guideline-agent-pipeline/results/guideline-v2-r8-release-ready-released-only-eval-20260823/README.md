# Guideline Group Evaluation

This report evaluates the offline guideline grouping itself. It does not use embedding scores, recall ranks, or known anchor locations.

## Summary

- Guidelines: 177
- Evaluated groups with case metadata: 56
- Source-only groups without case metadata: 121
- Assigned unique cases: 189 / 666
- Case coverage rate: 0.28378378378378377
- Pending candidate rows: 386
- Review queue included: False
- Small groups: 35
- Mixed HCVR groups: 6
- Mixed CWE groups: 5
- Weighted HCVR purity: 0.8307
- Weighted CWE purity: 0.9171

## Interpretation

Use this report as a diagnostic triage view for guideline releases, not as a hard pass/fail gate. A release can have clean mechanism groups but still perform poorly with a particular embedding model, and a release can improve recall while exposing overly broad or mixed guideline groups.
HCVR/CWE purity is computed only for groups that can be joined to unified case metadata; source-only historical CVE groups are reported separately instead of being treated as impure.
The structural labels are weak triage signals, not optimization targets and not the final definition of a good guideline. Mechanism quality should also be reviewed with human or LLM judging over the grouped CVE evidence, and final paper claims still require same-identity embedding recall.

## Flagged Groups

- `gl_mech_0005` `mech_path_traversal_missing_canonical_prefix`: cases=18, source_cves=48, flags=mixed_hcvr, HCVR=path_archive_traversal:0.61, CWE=unspecified:0.94
- `gl_mech_0011` `mech_path_traversal_missing_canonical_prefix`: cases=14, source_cves=38, flags=mixed_hcvr, HCVR=iris:0.50, CWE=unspecified:0.71
- `gl_mech_0022` `mech_xml_external_entity_resolution`: cases=13, source_cves=66, flags=mixed_hcvr,mixed_cwe, HCVR=unspecified:0.46, CWE=unspecified:0.54
- `gl_mech_0001` `mech_temp_file_delete_mkdir_race`: cases=8, source_cves=10, flags=mixed_hcvr, HCVR=toctou_check_use_race:0.62, CWE=unspecified:1.00
- `gl_mech_0035` `mech_deserialization_untrusted_type_graph`: cases=3, source_cves=15, flags=mixed_hcvr,mixed_cwe, HCVR=iris:0.67, CWE=unspecified:0.67
- `gl_mech_0093` `mech_binary_length_unbounded_resource_use`: cases=2, source_cves=12, flags=mixed_cwe, HCVR=unspecified:1.00, CWE=CWE-770:0.67
- `gl_mech_0164` `mech_authentication_artifact_incomplete_validation`: cases=2, source_cves=3, flags=mixed_hcvr,mixed_cwe, HCVR=authentication_session_token_validation:0.50, CWE=CWE-255:0.50
- `gl_mech_0170` `mech_object_owner_scope_missing_authz`: cases=2, source_cves=6, flags=mixed_cwe, HCVR=authorization_bypass:1.00, CWE=CWE-863:0.50
- `gl_mech_0004` `mech_object_owner_scope_missing_authz`: cases=1, source_cves=1, flags=small_group, HCVR=authorization_bypass:1.00, CWE=CWE-863:1.00
- `gl_mech_0007` `mech_ssrf_webhook_url_fetch`: cases=1, source_cves=4, flags=small_group, HCVR=ssrf:1.00, CWE=unspecified:1.00
- `gl_mech_0010` `mech_archive_symlink_extraction_escape`: cases=1, source_cves=1, flags=small_group, HCVR=iris:1.00, CWE=unspecified:1.00
- `gl_mech_0015` `mech_temp_file_delete_mkdir_race`: cases=1, source_cves=1, flags=small_group, HCVR=toctou_check_use_race:1.00, CWE=unspecified:1.00
- `gl_mech_0025` `mech_state_precondition_missing_before_effect`: cases=1, source_cves=1, flags=small_group, HCVR=toctou_check_use_race:1.00, CWE=unspecified:1.00
- `gl_mech_0027` `mech_authentication_artifact_incomplete_validation`: cases=1, source_cves=1, flags=small_group, HCVR=concurrent_object_lifecycle:1.00, CWE=unspecified:1.00
- `gl_mech_0028` `mech_request_body_resource_mismatch_authz`: cases=1, source_cves=1, flags=small_group, HCVR=ssrf:1.00, CWE=unspecified:1.00
- `gl_mech_0030` `mech_ssrf_webhook_url_fetch`: cases=1, source_cves=13, flags=small_group, HCVR=toctou_check_use_race:1.00, CWE=unspecified:1.00
- `gl_mech_0045` `mech_ldap_filter_unescaped_input`: cases=1, source_cves=8, flags=small_group, HCVR=unspecified:1.00, CWE=CWE-74:1.00
- `gl_mech_0046` `mech_jndi_untrusted_lookup_target`: cases=1, source_cves=6, flags=small_group, HCVR=iris:1.00, CWE=unspecified:1.00
- `gl_mech_0048` `mech_jndi_untrusted_lookup_target`: cases=1, source_cves=5, flags=small_group, HCVR=ssrf:1.00, CWE=unspecified:1.00
- `gl_mech_0050` `mech_ssrf_webhook_url_fetch`: cases=1, source_cves=4, flags=small_group, HCVR=ssrf:1.00, CWE=unspecified:1.00
