# Guideline LLM Judge Summary

This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.
It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration.

## Summary

- Judge inputs: 20
- Parsed outputs: 1
- Missing outputs: 19
- Invalid outputs: 0
- Accepted groups: 0
- Needs revision/split/merge/evidence: 1
- Low-score groups: 1 at threshold 0.6
- Decision counts: {'revise': 1}
- Average scores: {'coherence_score': 0.58, 'coverage_score': 0.08, 'actionability_score': 0.1, 'retrieval_query_quality': 0.05}

## Highest Priority Rows

- `gl_mech_0006` `mech_temp_file_delete_mkdir_race`: decision=missing, min_score=None, issue=
- `gl_mech_0007` `pending_mech_cluster_1_insecure_default_permissions_on_temporary_files_created_with_file_crea`: decision=missing, min_score=None, issue=
- `gl_mech_0008` `mech_path_traversal_missing_canonical_prefix`: decision=missing, min_score=None, issue=
- `gl_mech_0009` `mech_bean_property_reflection_escape`: decision=missing, min_score=None, issue=
- `gl_mech_0010` `mech_object_owner_scope_missing_authz`: decision=missing, min_score=None, issue=
- `gl_mech_0012` `pending_mech_cluster_3_unsanitized_input_in_dynamically_generated_code`: decision=missing, min_score=None, issue=
- `gl_mech_0014` `mech_path_traversal_missing_canonical_prefix`: decision=missing, min_score=None, issue=
- `gl_mech_0018` `pending_mech_cluster_4_missing_allow_list_for_inline_content_disposition_leading_to_xss`: decision=missing, min_score=None, issue=
- `gl_mech_0047` `mech_deserialization_untrusted_type_graph`: decision=missing, min_score=None, issue=
- `gl_mech_0050` `mech_jndi_untrusted_lookup_target`: decision=missing, min_score=None, issue=
- `gl_mech_0068` `pending_mech_cluster_13_direct_string_concatenation_into_sql_query`: decision=missing, min_score=None, issue=
- `gl_mech_0073` `pending_mech_cluster_14_sql_injection_mitigated_by_input_escaping`: decision=missing, min_score=None, issue=
- `gl_mech_0075` `mech_jndi_untrusted_lookup_target`: decision=missing, min_score=None, issue=
- `gl_mech_0082` `mech_privileged_server_side_capability_exposed`: decision=missing, min_score=None, issue=
- `gl_mech_0084` `pending_mech_cluster_16_incomplete_dom_node_handling_in_sanitization`: decision=missing, min_score=None, issue=
- `gl_mech_0087` `pending_mech_cluster_16_missing_context_dependent_output_encoding`: decision=missing, min_score=None, issue=
- `gl_mech_0118` `mech_toctou_mutable_object_reuse`: decision=missing, min_score=None, issue=
- `gl_mech_0129` `mech_missing_authentication_before_privileged_action`: decision=missing, min_score=None, issue=
- `gl_mech_0132` `pending_mech_cluster_23_missing_cryptographic_token_verification`: decision=missing, min_score=None, issue=
- `gl_mech_0001` `mech_deserialization_untrusted_type_graph`: decision=revise, min_score=0.05, issue=The supplied guideline describes general object deserialization with attacker-controlled type graphs, but the evidenced cases primarily concern unsafe XML parser configuration that permits DTD/external-entity processing (XXE). The source shape, sensitive behavior, required guard, and safe fixes are materially different.
