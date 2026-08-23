# Guideline Boundary Repair Pack

This artifact extracts the split/revise items from the evidence worklist.
It is review-only and does not change any released guideline, lexicon, sidecar, rank table, or audit prompt.

## Summary

- Repair rows: 8
- Repair kinds: {'revise_mechanism_text_from_evidence': 5, 'split_mechanism_boundary': 3}
- Example counts included: {'source_trace_present': 13, 'review_entry_only': 16, 'missing_trace_evidence': 4}

## Repair Items

| Priority | Guideline | Mechanism | Kind | Proposed Boundaries | Strong Examples | Weak Examples |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `gl_mech_0001` | `mech_temp_file_delete_mkdir_race` | `split_mechanism_boundary` | candidate_boundary_01,candidate_boundary_02 | centic9__jgit-cookbook::CVE-2022-4817,devent__globalpom-utils::CVE-2018-25068,fusesource__hawtjni::CVE-2013-2035 | junit-team__junit4::CVE-2020-15250,manydesigns__portofino::CVE-2022-3952 |
| 2 | `gl_mech_0022` | `mech_xml_external_entity_resolution` | `split_mechanism_boundary` | candidate_boundary_01,candidate_boundary_02,candidate_boundary_03 | allure-framework__allure2::CVE-2025-52888 | aws_amplify__aws_sdk_android::CVE-2022-4725,apache__cxf-fediz::CVE-2018-8038,archimatetool__archi::CVE-2023-40235,bonitasoft__bonita-connector-webservice::CVE-2020-36640 |
| 3 | `gl_mech_0116` | `mech_ssrf_redirect_following_client` | `split_mechanism_boundary` | candidate_boundary_01,candidate_boundary_02,candidate_boundary_03,candidate_boundary_04 | bigsk1__openai-realtime-ui::CVE-2026-5803,dhis2__dhis2-core::CVE-2022-41949 | cbioportal__cbioportal::CVE-2024-41668,hkuds__nanobot::CVE-2026-49138,jxxghp__moviepilot::CVE-2026-10107 |
| 4 | `gl_mech_0007` | `mech_ssrf_webhook_url_fetch` | `revise_mechanism_text_from_evidence` | candidate_revision | n/a | feiyuchuixue__sz-boot-parent::CVE-2026-3189 |
| 5 | `gl_mech_0011` | `mech_path_traversal_missing_canonical_prefix` | `revise_mechanism_text_from_evidence` | candidate_boundary_01,candidate_boundary_02 | cbeust__testng::CVE-2022-4065,codehaus-plexus__plexus-archiver::CVE-2018-1002200 | alibaba__one-java-agent::CVE-2022-25842,davemckain__qtiworks::CVE-2022-39367,diffplug__goomph::CVE-2022-26049,bspkrs__mcpmappingviewer::CVE-2022-4494 |
| 6 | `gl_mech_0015` | `mech_temp_file_delete_mkdir_race` | `revise_mechanism_text_from_evidence` | candidate_revision | n/a | psf__requests::CVE-2026-25645 |
| 7 | `gl_mech_0061` | `mech_open_redirect_unsafe_uri_scheme` | `revise_mechanism_text_from_evidence` | candidate_revision | aces__loris::CVE-2026-39985,chamilo__chamilo-lms::CVE-2025-66447,dspace__dspace::CVE-2022-31193 | adonisjs__http-server::CVE-2026-40255,atjiu__pybbs::CVE-2025-8813 |
| 8 | `gl_mech_0117` | `mech_ssrf_webhook_url_fetch` | `revise_mechanism_text_from_evidence` | candidate_revision | bugsink__bugsink::CVE-2026-44502,cc-tweaked__cc-tweaked::CVE-2023-37262 | backstage__backstage::CVE-2026-32236,bergskenop__blender-mcp::CVE-2026-10662,budibase__budibase::CVE-2026-31818 |

## Use Policy

- Use this pack before editing the mechanism lexicon or guideline sidecar.
- Treat proposed boundaries as hypotheses until source-level evidence assigns cases to them.
- Do not convert split suggestions, judge notes, case labels, or known anchors into runtime routing.
- After a boundary is promoted into recall-consumed text, rerun same-identity recall before making a paper-facing claim.
