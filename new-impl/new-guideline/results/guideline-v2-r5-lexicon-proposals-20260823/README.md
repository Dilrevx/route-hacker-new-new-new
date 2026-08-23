# Mechanism Lexicon Proposal Backlog

This artifact converts the r5 revision backlog into review-only lexicon proposals and recall investigation tasks.
It is not a guideline release and is not consumed by online recall.

## Summary

- Proposals: 50
- Proposal kinds: {'candidate_mechanism_revision': 8, 'candidate_new_mechanism': 9, 'evidence_collection_task': 8, 'recall_investigation_task': 25}
- Review statuses: {'needs_case_evidence': 8, 'needs_human_source_validation': 17, 'needs_same_identity_recall_debug': 25}
- Existing mechanisms touched: ['mech_bean_property_reflection_escape', 'mech_deserialization_untrusted_type_graph', 'mech_jndi_untrusted_lookup_target', 'mech_missing_authentication_before_privileged_action', 'mech_object_owner_scope_missing_authz', 'mech_open_redirect_unsafe_uri_scheme', 'mech_path_traversal_missing_canonical_prefix', 'mech_privileged_server_side_capability_exposed', 'mech_request_body_resource_mismatch_authz', 'mech_ssrf_webhook_url_fetch', 'mech_temp_file_delete_mkdir_race', 'mech_template_expression_untrusted_eval', 'mech_toctou_mutable_object_reuse', 'mech_xml_external_entity_resolution']

## First Items

| Proposal | Kind | Source Guideline | Mechanism | Status | Name / Issue |
| --- | --- | --- | --- | --- | --- |
| `proposal_f7a4a9207692` | `candidate_new_mechanism` | `gl_mech_0082` | `mech_privileged_server_side_capability_exposed` | `needs_human_source_validation` | Missing or inactive sanitizer/allowlist filter in restricted HTML-cleaning configurations, including unsafe elements, at |
| `proposal_346ac0b064b3` | `candidate_new_mechanism` | `gl_mech_0082` | `mech_privileged_server_side_capability_exposed` | `needs_human_source_validation` | Parser, normalization, serialization, or comment-handling discrepancies that preserve attacker-controlled markup despite |
| `proposal_c8bd17bd201e` | `candidate_new_mechanism` | `gl_mech_0082` | `mech_privileged_server_side_capability_exposed` | `needs_human_source_validation` | SafeHtml validator policy gaps specific to Hibernate Validator, if the exact rejected construct and post-fix policy are |
| `proposal_e99f93cf6401` | `candidate_new_mechanism` | `gl_mech_0075` | `mech_jndi_untrusted_lookup_target` | `needs_human_source_validation` | LDAP filter or distinguished-name injection through unescaped attacker-controlled values |
| `proposal_7828efbdc220` | `candidate_new_mechanism` | `gl_mech_0075` | `mech_jndi_untrusted_lookup_target` | `needs_human_source_validation` | Authorization bypass when an unknown requested policy/filter identifier resolves to null and is treated as unrestricted |
| `proposal_f1a3ccfb8804` | `candidate_new_mechanism` | `gl_mech_0005` | `mech_temp_file_delete_mkdir_race` | `needs_human_source_validation` | Temporary-resource TOCTOU |
| `proposal_133b5be5a405` | `candidate_new_mechanism` | `gl_mech_0005` | `mech_temp_file_delete_mkdir_race` | `needs_human_source_validation` | Temporary-resource permissions |
| `proposal_2047ef0974b9` | `candidate_new_mechanism` | `gl_mech_0007` | `mech_path_traversal_missing_canonical_prefix` | `needs_human_source_validation` | Archive entry name controls a resolved extraction target outside the intended root because containment is absent or inco |
| `proposal_2661f62cd724` | `candidate_new_mechanism` | `gl_mech_0007` | `mech_path_traversal_missing_canonical_prefix` | `needs_human_source_validation` | Archive extraction writes through an existing or earlier archive-created symbolic link despite lexical/canonical target |
| `proposal_e4e0df397297` | `candidate_mechanism_revision` | `gl_mech_0001` | `mech_deserialization_untrusted_type_graph` | `needs_human_source_validation` | The assigned case is anchored in an XML resource factory and the cluster summary describes insecure XML processing/XXE, while the guideline describes attacke... |
| `proposal_9f1540b58534` | `candidate_mechanism_revision` | `gl_mech_0009` | `mech_object_owner_scope_missing_authz` | `needs_human_source_validation` | The sole case is labeled template_expression_injection and the cluster summary describes unsafe expression evaluation, while the guideline describes missing ... |
| `proposal_0e79f4b1aef1` | `candidate_mechanism_revision` | `gl_mech_0118` | `mech_toctou_mutable_object_reuse` | `needs_human_source_validation` | The assigned cases consistently concern attacker-controlled binary-input size or length metadata driving parsing, allocation, buffering, decompression, or fr... |
| `proposal_fc336c876810` | `candidate_mechanism_revision` | `gl_mech_0084` | `pending_mech_cluster_16_incomplete_dom_node_handling_in_sanitization` | `needs_human_source_validation` | The two cases share one coherent sanitizer-bypass mechanism, but the guideline begins with an overbroad generic source-to-sink template and does not clearly ... |
| `proposal_a3bd9c359db7` | `candidate_mechanism_revision` | `gl_mech_0017` | `pending_mech_cluster_4_missing_allow_list_for_inline_content_disposition_leading_to_xss` | `needs_human_source_validation` | Both supplied cases share a clear stored-file download mechanism: a request-controlled attachment/inline choice allows browser-renderable content to be serve... |
| `proposal_b1cb57a3fb6c` | `candidate_mechanism_revision` | `gl_mech_0073` | `pending_mech_cluster_14_sql_injection_mitigated_by_input_escaping` | `needs_human_source_validation` | The assigned cases are consistently SQL-injection related, but the guideline is over-broad, introduces unrelated mechanisms, and recommends fragile escaping ... |
| `proposal_820780a860f3` | `candidate_mechanism_revision` | `gl_mech_0129` | `mech_missing_authentication_before_privileged_action` | `needs_human_source_validation` | The cases mostly involve accepting an authentication artifact with incomplete cryptographic, protocol, audience, signature, or proof-of-possession validation... |
| `proposal_ad9aa54b7b04` | `candidate_mechanism_revision` | `gl_mech_0002` | `mech_xml_external_entity_resolution` | `needs_human_source_validation` | The core XXE mechanism is coherent and well supported by several cases, but the guideline is overbroad: it treats XPath inputs and all XSLT processing as equ... |
| `proposal_3be75a4a130e` | `evidence_collection_task` | `gl_mech_0132` | `pending_mech_cluster_23_missing_cryptographic_token_verification` | `needs_case_evidence` | Only the NIMBLE case supplies mechanism evidence for accepting JWT claims without signature verification; the pac4j case has no vulnerability description or ... |
| `proposal_87330456fe52` | `evidence_collection_task` | `gl_mech_0087` | `pending_mech_cluster_16_missing_context_dependent_output_encoding` | `needs_case_evidence` | The proposed mechanism is plausible for the JStachio case, but two of the three assigned cases provide only patch-location anchors with no source-to-sink or ... |
| `proposal_58560f1ad3e5` | `evidence_collection_task` | `gl_mech_0006` | `pending_mech_cluster_1_insecure_default_permissions_on_temporary_files_created_with_file_crea` | `needs_case_evidence` | The intended temporary-resource permission mechanism is plausible, but neither case provides source behavior, patch semantics, or vulnerability description e... |
| `proposal_4e7935acda2b` | `evidence_collection_task` | `gl_mech_0050` | `mech_jndi_untrusted_lookup_target` | `needs_case_evidence` | The guideline is a coherent and actionable JNDI untrusted-lookup-target mechanism, but only the Axis case provides source-to-sink evidence. The DataEase case... |
| `proposal_ad221ceb9b4c` | `evidence_collection_task` | `gl_mech_0008` | `mech_bean_property_reflection_escape` | `needs_case_evidence` | The sole case is labeled template-expression injection, while the guideline describes bean-binding and reflective meta-property exposure; the payload provide... |
| `proposal_7b7287751edc` | `evidence_collection_task` | `gl_mech_0068` | `pending_mech_cluster_13_direct_string_concatenation_into_sql_query` | `needs_case_evidence` | The stated SQL-concatenation mechanism is plausible and the proposed parameterized-query fix is appropriate, but the supplied case records contain only file/... |
| `proposal_3b2b4352d75f` | `evidence_collection_task` | `gl_mech_0013` | `mech_path_traversal_missing_canonical_prefix` | `needs_case_evidence` | The guideline precisely describes traversal caused by resolving attacker-controlled path components without normalized containment, but most supplied cases p... |
| `proposal_776240a34ba6` | `evidence_collection_task` | `gl_mech_0047` | `mech_deserialization_untrusted_type_graph` | `needs_case_evidence` | The proposed mechanism is coherent, but only the Powsybl case supplies direct evidence of an unfiltered ObjectInputStream.readObject() path; the Seata and Em... |

## Promotion Rule

A proposal can enter `mechanism_lexicon.seed.json` only after reviewer-confirmed source/sink/guard evidence and a fresh same-identity recall run for the resulting guideline sidecar.
