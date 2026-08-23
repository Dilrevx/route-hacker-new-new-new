# Recall-Side Debug Pack

This pack lists semantically clean guideline groups whose joined recall rows still miss the primary Top-K budget.
It is a diagnosis artifact only: it does not change guidelines, sidecars, embedding weights, ranking, or audit prompts.

## Summary

- Recall label: `r7-p3c64-full143`
- Primary budget: Top-100
- Alignment join coverage: 28 / 143
- Debug groups: 6
- Miss states: {'coverage_gap_not_in_rank_table': 9, 'ranked_below_primary_budget': 6}
- Recommended checks: {'compare_embedding_backend_or_query_adapter_on_same_identity': 6, 'inspect_candidate_slicing_for_known_anchor_context': 6, 'inspect_guideline_query_wording_against_source_evidence': 6, 'review_label_mixture_without_treating_it_as_hard_failure': 2, 'verify_identity_filter_dataset_split_and_rank_table_coverage': 3}

## Debug Groups

| Guideline | Mechanism | Joined | Miss States | Checks | Example Misses |
| --- | --- | ---: | --- | --- | --- |
| `gl_mech_0001` | `mech_temp_file_delete_mkdir_race` | 1 | {"coverage_gap_not_in_rank_table": 7, "ranked_below_primary_budget": 1} | verify_identity_filter_dataset_split_and_rank_table_coverage,inspect_guideline_query_wording_against_source_evidence,inspect_candidate_slicing_for_known_anchor_context,compare_embedding_backend_or_query_adapter_on_same_identity,review_label_mixture_without_treating_it_as_hard_failure | centic9__jgit-cookbook::CVE-2022-4817@none:coverage_gap_not_in_rank_table,devent__globalpom-utils::CVE-2018-25068@none:coverage_gap_not_in_rank_table,fusesource__hawtjni::CVE-2013-2035@none:coverage_gap_not_in_rank_table,junit-team__junit4::CVE-2020-15250@none:coverage_gap_not_in_rank_table,manydesigns__portofino::CVE-2022-3952@none:coverage_gap_not_in_rank_table,openkm__document-management-system::CVE-2022-3969@none:coverage_gap_not_in_rank_table,pgjdbc__pgjdbc::CVE-2022-41946@none:coverage_gap_not_in_rank_table,swagger-api__swagger-codegen::CVE-2021-21363@136:ranked_below_primary_budget |
| `gl_mech_0170` | `mech_object_owner_scope_missing_authz` | 1 | {"coverage_gap_not_in_rank_table": 1, "ranked_below_primary_budget": 1} | verify_identity_filter_dataset_split_and_rank_table_coverage,inspect_guideline_query_wording_against_source_evidence,inspect_candidate_slicing_for_known_anchor_context,compare_embedding_backend_or_query_adapter_on_same_identity,review_label_mixture_without_treating_it_as_hard_failure | dspace__dspace::CVE-2021-41189@none:coverage_gap_not_in_rank_table,jeecgboot__jeecgboot::CVE-2025-14908@275:ranked_below_primary_budget |
| `gl_mech_0171` | `mech_request_body_resource_mismatch_authz` | 1 | {"coverage_gap_not_in_rank_table": 1, "ranked_below_primary_budget": 1} | verify_identity_filter_dataset_split_and_rank_table_coverage,inspect_guideline_query_wording_against_source_evidence,inspect_candidate_slicing_for_known_anchor_context,compare_embedding_backend_or_query_adapter_on_same_identity | apolloconfig__apollo::CVE-2024-43397@252:ranked_below_primary_budget,theonedev__onedev::CVE-2021-21246@none:coverage_gap_not_in_rank_table |
| `gl_mech_0046` | `mech_jndi_untrusted_lookup_target` | 1 | {"ranked_below_primary_budget": 1} | inspect_guideline_query_wording_against_source_evidence,inspect_candidate_slicing_for_known_anchor_context,compare_embedding_backend_or_query_adapter_on_same_identity | apache__axis-axis1-java::CVE-2023-51441@194:ranked_below_primary_budget |
| `gl_mech_0118` | `mech_toctou_mutable_object_reuse` | 1 | {"ranked_below_primary_budget": 1} | inspect_guideline_query_wording_against_source_evidence,inspect_candidate_slicing_for_known_anchor_context,compare_embedding_backend_or_query_adapter_on_same_identity | okta__okta-sdk-java::CVE-2025-66033@215:ranked_below_primary_budget |
| `gl_mech_0172` | `mech_sql_dynamic_query_untrusted_fragment` | 1 | {"ranked_below_primary_budget": 1} | inspect_guideline_query_wording_against_source_evidence,inspect_candidate_slicing_for_known_anchor_context,compare_embedding_backend_or_query_adapter_on_same_identity | steve-community__steve::CVE-2026-28230@218:ranked_below_primary_budget |

## Use Policy

- Inspect coverage gaps before blaming the embedding model.
- Inspect query wording, candidate slicing, embedding backend, and adapter behavior for joined Top-K misses.
- Do not convert missed identities, labels, or judge notes into runtime regex fallback or per-case routing.
- Keep paper claims separated: semantic guideline quality, same-identity recall delta, sidecar equivalence, and engineering fusion are different claims.
