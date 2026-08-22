# Guideline Revision Backlog

This backlog joins TraeX/LLM-as-judge output with recall-alignment diagnostics.
It is a review queue for the next guideline iteration, not a released guideline file and not a ranking rule.

## Summary

- Backlog rows: 20
- Judge summary: {'judge_input_count': 20, 'parsed_count': 20, 'accepted_count': 2, 'decision_counts': {'accept': 2, 'needs_evidence': 10, 'revise': 5, 'split': 3}, 'low_score_count': 14}
- Alignment summary: {'recall_label': None, 'baseline_label': None, 'same_identity_baseline': None, 'joined_recall_case_count': None, 'recall_case_count': None, 'primary_budget': None}
- Recommended actions: {'collect_source_sink_guard_evidence': 10, 'keep_as_control_group': 2, 'revise_mechanism_text_from_evidence': 5, 'split_mechanism_boundary': 3}
- Judge decisions: {'accept': 2, 'needs_evidence': 10, 'revise': 5, 'split': 3}
- Recall/guideline attention: {}

## Highest Priority Items

| Guideline | Mechanism | Decision | Min Score | Action | Attention | Issue |
| --- | --- | --- | ---: | --- | --- | --- |
| `gl_mech_0116` | `mech_ssrf_redirect_following_client` | split | 0.1300 | `split_mechanism_boundary` | n/a | The guideline is actionable for redirect-based SSRF, but the supplied cases primarily show direct unvalidated outbound URLs, renderer-triggered external-resource fetching, or cr... |
| `gl_mech_0022` | `mech_xml_external_entity_resolution` | split | 0.5800 | `split_mechanism_boundary` | n/a | The core XXE mechanism is coherent and well described, but the assigned set is explicitly mixed: several cases lack source-level evidence of external-entity resolution, while XP... |
| `gl_mech_0001` | `mech_temp_file_delete_mkdir_race` | split | 0.6200 | `split_mechanism_boundary` | n/a | The createTempFile-delete-mkdir TOCTOU mechanism is well supported for five cases, but three file_permission_temp_resource cases have no evidence of that sequence and may instea... |
| `gl_mech_0015` | `mech_temp_file_delete_mkdir_race` | revise | 0.2000 | `revise_mechanism_text_from_evidence` | n/a | The sole anchor supports a same-path existence-check-to-file-creation/write race during archive extraction, but the guideline specializes it into a Java createTempFile-delete-mk... |
| `gl_mech_0117` | `mech_ssrf_webhook_url_fetch` | revise | 0.5600 | `revise_mechanism_text_from_evidence` | n/a | The concrete cases support attacker-influenced outbound URL handling and incomplete destination policy enforcement, but the group is over-scoped as webhook/callback fetching and... |
| `gl_mech_0007` | `mech_ssrf_webhook_url_fetch` | revise | 0.5800 | `revise_mechanism_text_from_evidence` | n/a | The assigned case confirms a generic attacker-controlled download URL reaching URL.openStream, but the guideline is overly framed around webhook/callback flows and its claimed f... |
| `gl_mech_0011` | `mech_path_traversal_missing_canonical_prefix` | revise | 0.6100 | `revise_mechanism_text_from_evidence` | n/a | The evidenced cases coherently describe archive-entry path traversal leading to writes outside an extraction root, but the cluster summary also includes distinct infinite-loop/n... |
| `gl_mech_0061` | `mech_open_redirect_unsafe_uri_scheme` | revise | 0.8200 | `revise_mechanism_text_from_evidence` | n/a | The cases coherently concern untrusted redirect destinations reaching browser/server redirect sinks without a final canonical destination check, but the group name and wording o... |
| `gl_mech_0006` | `mech_request_body_resource_mismatch_authz` | needs_evidence | 0.0000 | `collect_source_sink_guard_evidence` | n/a | The guideline states a coherent request-body resource-identity mismatch authorization mechanism, but no assigned case evidence is available to establish that the two historical ... |
| `gl_mech_0008` | `mech_temp_file_delete_mkdir_race` | needs_evidence | 0.0000 | `collect_source_sink_guard_evidence` | n/a | The guideline describes a coherent and actionable delete-then-mkdir temporary-directory TOCTOU mechanism, but no assigned case evidence is provided to establish that it accurate... |
| `gl_mech_0009` | `mech_template_expression_untrusted_eval` | needs_evidence | 0.0000 | `collect_source_sink_guard_evidence` | n/a | No assigned case metadata or examples are available, and the supplied cluster summary describes path/resource traversal rather than template or expression evaluation. |
| `gl_mech_0012` | `mech_html_sanitizer_policy_gap` | needs_evidence | 0.0000 | `collect_source_sink_guard_evidence` | n/a | The sanitizer-policy guideline is internally actionable, but no case-level evidence is provided and the cluster summary combines CSV formula injection, stored XSS, and response-... |
| `review_mech_0017` | `pending_mech_cluster_2_missing_or_insufficient_path_validation_for_file_and_resource_access` | needs_evidence | 0.0800 | `collect_source_sink_guard_evidence` | n/a | The proposed guideline is a generic missing-guard template rather than a path-traversal mechanism, and the supplied anchors contain no source snippets, dataflow, sink, or patch ... |
| `review_mech_0509` | `pending_mech_cluster_89_authentication_bypass_and_token_validation_flaws` | needs_evidence | 0.1200 | `collect_source_sink_guard_evidence` | n/a | The proposed mechanism is an over-broad missing-guard template. The payload provides only generic labels and patch-derived review windows, not the source/patch semantics needed ... |
| `review_mech_0514` | `pending_mech_cluster_89_missing_validation_in_authentication_authorization_flows` | needs_evidence | 0.2200 | `collect_source_sink_guard_evidence` | n/a | The proposed mechanism is too broad and the supplied evidence only substantiates distinct authentication-state failures in two cases; it does not establish that the authorizatio... |
| `gl_mech_0040` | `mech_template_expression_untrusted_eval` | needs_evidence | 0.3500 | `collect_source_sink_guard_evidence` | n/a | The guideline is a sound generic template/EL-injection review pattern, but the supplied anchors and trace notes do not establish its source-to-evaluator mechanism for most assig... |
| `review_mech_0513` | `pending_mech_cluster_89_jwt_signature_verification_and_algorithm_handling_failures` | needs_evidence | 0.4000 | `collect_source_sink_guard_evidence` | n/a | The intended JWT signature/algorithm-validation mechanism is plausible, but only one case provides source-level confirmation. The other three provide review-window anchors witho... |
| `gl_mech_0005` | `mech_path_traversal_missing_canonical_prefix` | needs_evidence | 0.7100 | `collect_source_sink_guard_evidence` | n/a | The stated mechanism is coherent and actionable, but most displayed cases provide only patch-derived review windows rather than source-to-sink evidence; the group also carries a... |
| `gl_mech_0004` | `mech_object_owner_scope_missing_authz` | accept | 0.8800 | `keep_as_control_group` | n/a | The sole case directly matches missing authorization bound to the exact affected object: a creator can overwrite an existing same-name item that is hidden from them. The cluster... |
| `gl_mech_0010` | `mech_archive_symlink_extraction_escape` | accept | 0.9100 | `keep_as_control_group` | n/a | The single case directly supports the stated archive-created or pre-existing symlink-following write mechanism; physical extraction order is an important exploit precondition an... |

## Use Policy

- Use this file to choose which guideline groups to reread against source evidence.
- Do not copy judge-suggested text directly into the release without checking source/sink/guard evidence.
- Do not convert issue strings, split suggestions, or example misses into regex routing rules.
- A later paper-facing recall claim still needs a fresh same-identity recall comparison for the revised guideline sidecar.
