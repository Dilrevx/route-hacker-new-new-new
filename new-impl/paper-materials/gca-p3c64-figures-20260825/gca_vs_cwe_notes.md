# GCA vs CVE/CWE Visualization Notes

## Coverage Funnel

| Stage | Cases | Rate |
| --- | ---: | ---: |
| Primary released sidecar | 28 / 143 | 19.6% |
| Release current review queue | 53 / 143 | 37.1% |
| Release noise/singleton candidates | 73 / 143 | 51.0% |
| All CVE IDs ingested | 136 / 143 | 95.1% |
| CVE + GHSA supported | 143 / 143 | 100.0% |

## Current Coverage Categories

| Category | Count | Rate |
| --- | ---: | ---: |
| `missing_from_cve_clustering_raw_structured` | 63 | 44.1% |
| `covered_by_primary_sidecar` | 28 | 19.6% |
| `clustered_but_review_only_release_gate` | 25 | 17.5% |
| `present_in_raw_but_cluster_noise` | 20 | 14.0% |
| `ghsa_or_non_cve_no_cvelist_join` | 7 | 4.9% |

## CWE Labels With Many GCA Mechanisms

| CWE | Distinct mechanisms | Top mechanisms |
| --- | ---: | --- |
| CWE-20 | 18 | `mech_path_traversal_missing_canonical_prefix` (43), `mech_ssrf_webhook_url_fetch` (42), `mech_ssrf_redirect_following_client` (24), `mech_binary_length_unbounded_resource_use` (23) |
| CWE-862 | 12 | `mech_object_owner_scope_missing_authz` (16), `mech_request_body_resource_mismatch_authz` (12), `mech_ssrf_webhook_url_fetch` (5), `mech_privileged_server_side_capability_exposed` (4) |
| CWE-200 | 8 | `mech_path_traversal_missing_canonical_prefix` (3), `mech_ssrf_redirect_following_client` (3), `mech_temp_file_delete_mkdir_race` (2), `mech_ssrf_webhook_url_fetch` (2) |
| CWE-918 | 7 | `mech_ssrf_webhook_url_fetch` (69), `mech_ssrf_redirect_following_client` (30), `mech_open_redirect_unsafe_uri_scheme` (5), `mech_request_body_resource_mismatch_authz` (4) |
| CWE-79 | 7 | `mech_html_sanitizer_policy_gap` (44), `mech_inline_content_disposition_xss` (7), `mech_template_expression_untrusted_eval` (5), `mech_sql_dynamic_query_untrusted_fragment` (5) |
| CWE-863 | 7 | `mech_missing_authentication_before_privileged_action` (7), `mech_object_owner_scope_missing_authz` (6), `mech_ssrf_webhook_url_fetch` (5), `mech_request_body_resource_mismatch_authz` (4) |
| CWE-184 | 7 | `mech_deserialization_untrusted_type_graph` (5), `mech_jndi_untrusted_lookup_target` (3), `mech_html_sanitizer_policy_gap` (3), `mech_ssrf_webhook_url_fetch` (2) |
| CWE-284 | 7 | `mech_privileged_server_side_capability_exposed` (2), `mech_request_body_resource_mismatch_authz` (2), `mech_archive_symlink_extraction_escape` (1), `mech_path_traversal_missing_canonical_prefix` (1) |

## GCA Mechanisms Spanning Many CWE Labels

| Mechanism | Distinct CWE labels | Top CWE labels |
| --- | ---: | --- |
| `mech_ssrf_webhook_url_fetch` | 46 | CWE-918 (69), CWE-20 (42), CWE-670 (6), CWE-306 (6), CWE-862 (5) |
| `mech_path_traversal_missing_canonical_prefix` | 27 | CWE-22 (154), CWE-20 (43), CWE-59 (16), CWE-73 (13), CWE-367 (7) |
| `mech_binary_length_unbounded_resource_use` | 26 | CWE-770 (26), CWE-20 (23), CWE-190 (7), CWE-400 (7), CWE-787 (4) |
| `mech_ssrf_redirect_following_client` | 21 | CWE-918 (30), CWE-20 (24), CWE-601 (5), CWE-200 (3), CWE-330 (2) |
| `mech_request_body_resource_mismatch_authz` | 21 | CWE-862 (12), CWE-20 (7), CWE-639 (5), CWE-918 (4), CWE-863 (4) |
| `mech_sql_dynamic_query_untrusted_fragment` | 19 | CWE-89 (46), CWE-20 (22), CWE-79 (5), CWE-502 (3), CWE-94 (3) |
| `mech_xml_external_entity_resolution` | 16 | CWE-611 (62), CWE-20 (3), CWE-776 (3), CWE-502 (3), CWE-94 (3) |
| `mech_template_expression_untrusted_eval` | 15 | CWE-95 (13), CWE-94 (13), CWE-74 (11), CWE-20 (6), CWE-79 (5) |

## Paper Claim Boundary

These figures support a data-quality and query-construction claim: CWE/CVE metadata is too coarse or incomplete for direct retrieval queries, while GCA mechanism grouping creates more actionable audit obligations. They do not by themselves prove final vulnerability detection recall.
