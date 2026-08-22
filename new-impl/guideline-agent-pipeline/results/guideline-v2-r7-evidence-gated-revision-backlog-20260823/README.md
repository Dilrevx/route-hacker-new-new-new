# Guideline Revision Backlog

This backlog joins TraeX/LLM-as-judge output with recall-alignment diagnostics.
It is a review queue for the next guideline iteration, not a released guideline file and not a ranking rule.

## Summary

- Backlog rows: 20
- Judge summary: {'judge_input_count': 20, 'parsed_count': 20, 'accepted_count': 1, 'decision_counts': {'accept': 1, 'needs_evidence': 12, 'revise': 4, 'split': 3}, 'low_score_count': 17}
- Alignment summary: {'recall_label': None, 'baseline_label': None, 'same_identity_baseline': None, 'joined_recall_case_count': None, 'recall_case_count': None, 'primary_budget': None}
- Recommended actions: {'collect_source_sink_guard_evidence': 12, 'keep_as_control_group': 1, 'revise_mechanism_text_from_evidence': 4, 'split_mechanism_boundary': 3}
- Judge decisions: {'accept': 1, 'needs_evidence': 12, 'revise': 4, 'split': 3}
- Recall/guideline attention: {}

## Highest Priority Items

| Guideline | Mechanism | Decision | Min Score | Action | Attention | Issue |
| --- | --- | --- | ---: | --- | --- | --- |
| `gl_mech_0003` | `pending_mech_cluster_1_incomplete_handling_of_bundle_item_interactions_in_inventory` | split | 0.1200 | `split_mechanism_boundary` | n/a | The group combines three distinct inventory-state mechanisms: Bundle-specific event/render handling, player-scoped storage writes, and reconciliation between GUI slots and backi... |
| `gl_mech_0534` | `mech_object_owner_scope_missing_authz` | split | 0.4600 | `split_mechanism_boundary` | n/a | The two evidenced cases share a broad authorization-bypass outcome but use different mechanisms: one selects an incorrect authorization policy during group/object resolution, wh... |
| `gl_mech_0001` | `mech_temp_file_delete_mkdir_race` | split | 0.6200 | `split_mechanism_boundary` | n/a | The createTempFile-delete-mkdir race is a coherent and actionable mechanism, but three assigned file-permission temporary-resource cases lack evidence that they perform this rel... |
| `gl_mech_0004` | `pending_mech_cluster_1_missing_access_control_for_slot_modifications` | revise | 0.2400 | `revise_mechanism_text_from_evidence` | n/a | The mechanism is plausibly a slot-capability/precondition failure, but the guideline is overly generic and labels it as access control despite the available evidence specificall... |
| `gl_mech_0133` | `pending_mech_cluster_23_replace_backtracking_regex_engine_with_linear_time_alternative` | revise | 0.2800 | `revise_mechanism_text_from_evidence` | n/a | The two evidenced cases share a specific ReDoS mechanism, but the guideline is generic missing-guard boilerplate that incorrectly broadens the source and sink beyond regex evalu... |
| `gl_mech_0229` | `pending_mech_cluster_41_crlf_injection_due_to_missing_header_value_validation` | revise | 0.5800 | `revise_mechanism_text_from_evidence` | n/a | The two assigned cases plausibly share unsafe HTTP header construction without CR/LF validation, but the guideline's generic source-to-sink language and broad cluster summary di... |
| `gl_mech_0026` | `mech_path_traversal_missing_canonical_prefix` | revise | 0.7200 | `revise_mechanism_text_from_evidence` | n/a | The evidenced cases consistently concern archive-entry extraction into a destination directory without containment validation, but the guideline is overly broad: it includes arb... |
| `gl_mech_0509` | `pending_mech_cluster_89_authentication_bypass_and_token_validation_flaws` | needs_evidence | 0.0800 | `collect_source_sink_guard_evidence` | n/a | The shared label and broad cluster summary do not establish a common source-to-sink mechanism across the four cases. The supplied anchors lack vulnerability descriptions, patch ... |
| `gl_mech_0017` | `pending_mech_cluster_2_missing_or_insufficient_path_validation_for_file_and_resource_access` | needs_evidence | 0.1200 | `collect_source_sink_guard_evidence` | n/a | The intended path-containment mechanism is plausible for several labels, but the supplied anchors and empty descriptions do not establish a common source-to-path-construction-to... |
| `gl_mech_0265` | `pending_mech_cluster_46_missing_validation_of_cryptographic_parameters_and_keys` | needs_evidence | 0.1200 | `collect_source_sink_guard_evidence` | n/a | The supplied cases contain only patch-derived review-entry locations and no source, patch, or vulnerability descriptions establishing that either case involves missing validatio... |
| `gl_mech_0331` | `pending_mech_cluster_60_missing_restrictive_file_permissions_on_sensitive_files` | needs_evidence | 0.1500 | `collect_source_sink_guard_evidence` | n/a | The stated mechanism is missing restrictive permissions, but the cluster summary describes symlink/path-containment flaws; neither case provides source, patch, or vulnerability ... |
| `gl_mech_0137` | `pending_mech_cluster_25_information_leakage_due_to_missing_redaction` | needs_evidence | 0.2000 | `collect_source_sink_guard_evidence` | n/a | One case has no vulnerability description or trace evidence, while the evidenced Snowflake case is specifically a debug-log disclosure of encryption material. The guideline is o... |
| `gl_mech_0406` | `pending_mech_cluster_74_authentication_bypass_via_untrusted_headers_or_loopback_trust` | needs_evidence | 0.2500 | `collect_source_sink_guard_evidence` | n/a | Only the OneDev example substantiates an authentication bypass caused by trusting an attacker-controlled X-Forwarded-For header for loopback authorization. The BlueBubbles examp... |
| `gl_mech_0514` | `pending_mech_cluster_89_missing_validation_in_authentication_authorization_flows` | needs_evidence | 0.2800 | `collect_source_sink_guard_evidence` | n/a | The group is broadly auth-related, but the supplied evidence supports at least two different mechanisms—accepting inactive account identifiers and treating anonymous/failed reme... |
| `gl_mech_0513` | `pending_mech_cluster_89_jwt_signature_verification_and_algorithm_handling_failures` | needs_evidence | 0.3500 | `collect_source_sink_guard_evidence` | n/a | Only the NIMBLE case provides mechanism evidence for accepting a JWT without verified signature; the other three cases provide anchors and labels but no source, sink, missing gu... |
| `gl_mech_0507` | `mech_authentication_artifact_incomplete_validation` | needs_evidence | 0.4200 | `collect_source_sink_guard_evidence` | n/a | The Micronaut case clearly fits incomplete OIDC ID-token claim validation, but the Keystone case provides neither a vulnerability description nor trace evidence, so the shared m... |
| `gl_mech_0009` | `mech_path_traversal_missing_canonical_prefix` | needs_evidence | 0.4800 | `collect_source_sink_guard_evidence` | n/a | The guideline is a coherent and actionable path-containment mechanism, but most displayed cases provide only patch-derived review-window labels rather than source-to-sink eviden... |
| `gl_mech_0302` | `mech_binary_length_unbounded_resource_use` | needs_evidence | 0.5200 | `collect_source_sink_guard_evidence` | n/a | The guideline describes a plausible and actionable resource-consumption mechanism, but the supplied case evidence contains only changed-file spans. It does not establish that bo... |
| `gl_mech_0047` | `mech_xml_external_entity_resolution` | needs_evidence | 0.5500 | `collect_source_sink_guard_evidence` | n/a | The guideline precisely describes XXE/external-resource resolution, and several supplied cases support it, but evidence is missing for most assigned cases and at least one visib... |
| `gl_mech_0079` | `mech_deserialization_untrusted_type_graph` | accept | 0.8800 | `keep_as_control_group` | n/a | The three cases consistently indicate general-purpose object deserialization on attacker-reachable or insufficiently trusted input. The main case-specific uncertainty is the exa... |

## Use Policy

- Use this file to choose which guideline groups to reread against source evidence.
- Do not copy judge-suggested text directly into the release without checking source/sink/guard evidence.
- Do not convert issue strings, split suggestions, or example misses into regex routing rules.
- A later paper-facing recall claim still needs a fresh same-identity recall comparison for the revised guideline sidecar.
