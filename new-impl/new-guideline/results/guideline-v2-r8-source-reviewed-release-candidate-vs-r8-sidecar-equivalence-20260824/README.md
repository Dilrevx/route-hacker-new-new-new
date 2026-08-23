# Guideline Sidecar Equivalence

This report compares guideline sidecars by the key and guideline text that the recall runner consumes.
It intentionally ignores release-only metadata that does not affect `apply_guideline_overrides()`.

## Summary

- Left: `guideline-v2-r8-release-ready-sidecar`
- Right: `source-reviewed-release-candidate-sidecar`
- Left rows: 189
- Right rows: 32
- Common rows: 28
- Same key set: False
- Changed consumed guideline texts: 28
- Recall-consumed text equivalent: False

## Boundary

If `recall_consumed_text_equivalent` is true, a deterministic recall runner with the same identity file, snapshots, candidate slicing, embedding backend, and ranking parameters should produce the same rankings even if the sidecar files differ in non-consumed metadata.
This equivalence report is evidence for reusing an existing same-identity recall table only under those unchanged runtime conditions.

## Changed Text Sample

- `aces__loris::CVE-2026-39985`
- `allure-framework__allure2::CVE-2025-52888`
- `apache__cxf-fediz::CVE-2018-8038`
- `aws_amplify__aws_sdk_android::CVE-2022-4725`
- `bigsk1__openai-realtime-ui::CVE-2026-5803`
- `bonitasoft__bonita-connector-webservice::CVE-2020-36640`
- `browserup__browserup-proxy::CVE-2020-26282`
- `bugsink__bugsink::CVE-2026-44502`
- `cbeust__testng::CVE-2022-4065`
- `cbioportal__cbioportal::CVE-2024-41668`
- `cc-tweaked__cc-tweaked::CVE-2023-37262`
- `centic9__jgit-cookbook::CVE-2022-4817`
- `codehaus-plexus__plexus-archiver::CVE-2018-1002200`
- `devent__globalpom-utils::CVE-2018-25068`
- `dhis2__dhis2-core::CVE-2022-41949`
- `dropwizard__dropwizard::CVE-2020-11002`
- `dropwizard__dropwizard::CVE-2020-5245`
- `dspace__dspace::CVE-2022-31193`
- `dspace__dspace::CVE-2022-31194`
- `dspace__dspace::CVE-2022-31195`
