# IRIS 213 CWE-Bench-Java Status Snapshot

Document status: portable experiment snapshot
Updated: 2026-08-24
Scope: full 213-case CWE-Bench-Java / IRIS universe.

This snapshot records the current best-effort state for running native IRIS and the official CodeQL baseline on the 213-case CWE-Bench-Java / IRIS dataset. It separates build/runtime eligibility from detection metrics. A CodeQL database being usable means the case can enter the native IRIS or official CodeQL workflow; it is not counted as a vulnerability detection result by itself.

## Headline Status

| Item | Count |
| --- | ---: |
| Full dataset denominator | 213 |
| Paired native IRIS + official CodeQL completed_verified cases | 62 |
| Native IRIS completed_verified cases | 62 |
| Official CodeQL completed_verified cases | 62 |
| Cases with CodeQL DB usable evidence | 93 |
| DB-usable cases not in final paired comparison | 31 |
| Cases without usable CodeQL DB evidence yet | 120 |

## Repair Waves

| Wave | Scope | codeql_db_repaired | no_safe_llm_repair | repair_attempt_failed | Notes |
| --- | ---: | ---: | ---: | ---: | --- |
| Historical r3 | 53 | 8 | 43 | 2 | Preflight source rebuild wave. |
| Latest r8 actual run | 94 | 55 | 39 | 0 | Explicit Maven mirror and 429 retry handling. |
| Latest 96 accounting | 96 | 55 | 41 | 0 | r8 plus two retained no-safe rows from r5: `OWASP__json-sanitizer_CVE-2020-13973_1.2.0` and `SpringSource__spring-security-oauth_CVE-2018-1260_2.3.2.RELEASE`. |
| r3 plus latest 96 unique | 149 | 63 | 84 | 2 | Combined repair-attempt ledger; not equal to final native IRIS completion. |

## Final Comparison Metrics

| Method | Denominator | Completed | Hits | Best-effort recall | Completed-subset recall | Reported paths | Fix-method overlap paths | Path overlap rate | Precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Official CodeQL | 213 | 62 | 12 | 0.056 | 0.194 | 427 | 171 | 0.400 | unavailable |
| Native IRIS vanilla | 213 | 62 | 17 | 0.080 | 0.274 | 6008 | 447 | 0.074 | unavailable |
| Native IRIS posthoc | 213 | 62 | 16 | 0.075 | 0.258 | 621 | 125 | 0.201 | unavailable |

Precision is intentionally unavailable. The IRIS fix-method labels provide positive targets for method recall and path-overlap accounting, but they do not define a complete false-positive set.

## 213-Case Status Buckets

| Category | Cases |
| --- | ---: |
| `codeql_db_not_repaired` | 79 |
| `paired_completed` | 62 |
| `historical_codeql_not_usable` | 23 |
| `codeql_first_build_not_usable` | 18 |
| `db_usable_admission_rejected` | 16 |
| `db_usable_admitted_native_not_completed` | 15 |

Bucket meanings:

- `paired_completed`: both native IRIS and official CodeQL have `completed_verified` summaries and enter the final paired comparison.
- `db_usable_admitted_native_not_completed`: the case has usable DB evidence and passed strict native IRIS admission, but no completed native IRIS summary is present in the final report.
- `db_usable_admission_rejected`: the case has usable DB evidence, but failed strict native IRIS admission because required official metadata or native query support is missing.
- `codeql_db_not_repaired`: repair attempts ended with no safe deterministic build/DB repair under the exact-source contract.
- `historical_codeql_not_usable`: older matrix rows without usable DB evidence, including failed or unavailable historical repair states.
- `codeql_first_build_not_usable`: first-build or source-materialization failures before the latest repair waves produced usable DB evidence.

## Missing CodeQL DB Detail

| Category | Cases |
| --- | ---: |
| `no_safe_llm_repair` | 89 |
| `repair_attempt_failed` | 9 |
| `source_receipt_missing` | 9 |
| `no_safe_initial_build_command` | 6 |
| `iris_materialization_not_selected` | 3 |
| `build_command_discovery_failed` | 2 |
| `codeql_db_failed` | 1 |
| `llm_repair_worker_failed` | 1 |

## DB Usable But Not In Final Paired Comparison

| Category | Cases |
| --- | ---: |
| `strict native admission passed, but no completed_verified native IRIS summary in final 213 report` | 15 |
| `project_info_missing_or_ambiguous;exact_source_receipt_missing;package_names_missing;native_query_unsupported` | 3 |
| `project_info_missing_or_ambiguous;fix_info_missing;package_names_missing;native_query_unsupported` | 3 |
| `project_info_missing_or_ambiguous;package_names_missing;native_query_unsupported` | 3 |
| `exact_source_receipt_missing;package_names_missing` | 2 |
| `project_info_missing_or_ambiguous;fix_info_missing;exact_source_receipt_missing;package_names_missing;native_query_unsupported` | 2 |
| `exact_source_receipt_missing` | 1 |
| `fix_info_missing` | 1 |
| `project_info_missing_or_ambiguous;exact_source_receipt_missing;package_names_missing` | 1 |

## Contract Boundaries

- The full denominator remains 213 cases.
- Native IRIS completion counts only `summary.status == completed_verified` with verified completion.
- Official CodeQL completion counts only its baseline `completed_verified` summary.
- Repair workers preserve exact source, forbid source edits and source revision substitution, forbid official query changes, and do not consume retrieval or target-truth data.
- CodeQL DB construction is an admission/runnability artifact, not a detection result.
- Reported recall is best-effort method recall against IRIS fix-method labels; path overlap is an overlap proxy over reported paths.

## Source Artifacts

| Artifact | SHA256 |
| --- | --- |
| `comparison.213.json` | `084dcece25b2ece1a5f68b2cd6dee3cbe4f4458154406c336afb641a55244984` |
| `iris213_current_coverage_matrix.jsonl` | `76d47bc64db4eec2caeba3adbb431a442f3919b373c51b434261099e86f54488` |
| `r3_w1_llm_repair_receipts.jsonl` | `40ead4e48f8191570537a3aed9f622eea437e319841a52c98ce43b1ce68a999e` |
| `r8_w1_llm_repair_receipts.jsonl` | `97cc1c523a735836b9d045396e5f20b253bc6f739f2483608b7da1681f5620bc` |
| `r5_w1_llm_repair_receipts.jsonl` | `4b858c48a882e99c5df5623c18ee242560b1f6a379ccbdfb2e0cda3a8aa6edbe` |
| `strict-admission.jsonl` | `34b97d91a5fb5e8325e6251ff2699d1ef4821b0699f91d7baf83f4a5bc7f1f72` |
| `strict-admission.summary.json` | `819b3e39d077398d9259366979de0c629e7d2c4a9ce66691b9a5d14e22716266` |

The machine-readable files in this directory are:

- [`iris213_case_status.csv`](iris213_case_status.csv): one row per case.
- [`iris213_status_summary.json`](iris213_status_summary.json): aggregate counts, metric payloads, and provenance hashes.

## Per-Case Ledger

| # | Case | Query | Bucket | DB usable | Repair wave | Repair status | Native admission | Native status | CodeQL status | Recall flags | Detail |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `perwendel__spark_CVE-2018-9159_2.7.1` | `cwe-022wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | vanilla, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=False; codeql_hit=True |
| 2 | `perwendel__spark_CVE-2016-9177_2.5.1` | `cwe-022wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | vanilla, posthoc, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=True |
| 3 | `square__retrofit_CVE-2018-1000850_2.4.0` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 4 | `dromara__hutool_CVE-2018-17297_4.1.11` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=True |
| 5 | `vert-x3__vertx-web_CVE-2018-12542_3.5.3.CR1` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 6 | `apache__jspwiki_CVE-2019-0225_2.11.0.M2` | `cwe-022wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 7 | `wildfly__wildfly_CVE-2018-1047_11.0.0.Final` | `cwe-022wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 8 | `DSpace__DSpace_CVE-2016-10726_4.4` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 9 | `apache__tika_CVE-2018-11762_1.18` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=False |
| 10 | `codehaus-plexus__plexus-archiver_CVE-2018-1002200_3.5` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=False |
| 11 | `whitesource__curekit_CVE-2022-23082_1.1.3` | `cwe-022wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 12 | `zeroturnaround__zt-zip_CVE-2018-1002201_1.12` | `cwe-022wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 13 | `jlangch__venice_CVE-2022-36007_1.10.16` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 14 | `srikanth-lingala__zip4j_CVE-2018-1002202_1.3.2` | `cwe-022wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 15 | `testng-team__testng_CVE-2022-4065_7.5` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 16 | `asf__tapestry-5_CVE-2019-0207_5.4.4` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 17 | `asf__commons-io_CVE-2021-29425_2.6` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 18 | `diffplug__goomph_CVE-2022-26049_3.37.1` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `` | `not_admitted` | `not_completed` | `not_completed` | none | iris_materialization_not_selected |
| 19 | `ESAPI__esapi-java-legacy_CVE-2022-23457_2.2.3.1` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 20 | `alibaba__one-java-agent_CVE-2022-25842_0.0.1` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=True |
| 21 | `joniles__mpxj_CVE-2020-35460_8.3.4` | `cwe-022wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 22 | `codehaus-plexus__plexus-utils_CVE-2022-4244_3.0.23` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=True |
| 23 | `undertow-io__undertow_CVE-2014-7816_1.0.16.Final` | `cwe-022wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 24 | `codehaus-plexus__plexus-archiver_CVE-2023-37460_4.7.1` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=False |
| 25 | `jeremylong__DependencyCheck_CVE-2018-12036_3.1.2` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=True |
| 26 | `apache__rocketmq_CVE-2019-17572_4.6.0` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 27 | `vert-x3__vertx-web_CVE-2019-17640_3.9.3` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 28 | `apache__sling-org-apache-sling-servlets-resolver_CVE-2024-23673_2.10.0` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 29 | `x-stream__xstream_CVE-2013-7285_1.4.6` | `cwe-078wLLM` | `historical_codeql_not_usable` | no | `none` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 30 | `apache__myfaces_CVE-2011-4367_2.0.11` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=True |
| 31 | `spring-cloud__spring-cloud-config_CVE-2020-5405_2.1.6.RELEASE` | `cwe-022wLLM` | `paired_completed` | yes | `historical-r3-53` | `no_safe_llm_repair` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 32 | `spring-cloud__spring-cloud-config_CVE-2020-5410_2.1.8.RELEASE` | `cwe-022wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | codeql | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=True |
| 33 | `x-stream__xstream_CVE-2021-21345_1.4.15` | `cwe-078wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 34 | `codehaus-plexus__plexus-utils_CVE-2017-1000487_3.0.15` | `cwe-078wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 35 | `asf__james-project_CVE-2022-22931_3.6.0` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 36 | `DSpace__DSpace_CVE-2022-31194_5.10` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=True |
| 37 | `DSpace__DSpace_CVE-2022-31195_5.10` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc, codeql | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=True |
| 38 | `xwiki__xwiki-commons_CVE-2022-24897_12.6.6` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 39 | `apache__dolphinscheduler_CVE-2022-26884_2.0.5` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 40 | `kubernetes-client__java_CVE-2020-8570_client-java-parent-9.0.1` | `cwe-022wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 41 | `jenkinsci__git-client-plugin_CVE-2019-10392_2.8.4` | `cwe-078wLLM` | `historical_codeql_not_usable` | no | `none` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 42 | `jenkinsci__perfecto-plugin_CVE-2020-2261_1.17` | `cwe-078wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 43 | `nahsra__antisamy_CVE-2017-14735_1.5.6` | `cwe-079wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `repair_attempt_failed` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 44 | `nahsra__antisamy_CVE-2016-10006_1.5.3` | `cwe-079wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 45 | `jenkinsci__workflow-cps-global-lib-plugin_CVE-2022-25174_544.vff04fa68714d` | `cwe-078wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 46 | `jenkinsci__docker-commons-plugin_CVE-2022-20617_1.17` | `cwe-078wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 47 | `jenkinsci__workflow-multibranch-plugin_CVE-2022-25175_706.vd43c65dec013` | `cwe-078wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 48 | `apache__shiro_CVE-2023-34478_1.11.0` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 49 | `apache__mina-sshd_CVE-2023-35887_2.9.2` | `cwe-022wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 50 | `OWASP__json-sanitizer_CVE-2020-13973_1.2.0` | `cwe-079wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_failed` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 51 | `apache__shiro_CVE-2023-46749_1.12.0` | `cwe-022wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 52 | `x-stream__xstream_CVE-2020-26217_1.4.14-java7` | `cwe-078wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 53 | `ESAPI__esapi-java-legacy_CVE-2022-24891_2.2.3.1` | `cwe-079wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=False |
| 54 | `nahsra__antisamy_CVE-2022-29577_1.6.6.1` | `cwe-079wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 55 | `nahsra__antisamy_CVE-2022-28367_1.6.5` | `cwe-079wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 56 | `xuxueli__xxl-job_CVE-2020-29204_2.2.0` | `cwe-079wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 57 | `jenkinsci__script-security-plugin_CVE-2023-24422_1228.vd93135a_2fb_25` | `cwe-078wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 58 | `apache__sling-org-apache-sling-xss_CVE-2016-5394_1.0.8` | `cwe-079wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 59 | `rhuss__jolokia_CVE-2018-1000129_1.4.0` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 60 | `yamcs__yamcs_CVE-2023-45278_5.8.6` | `cwe-022wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 61 | `yamcs__yamcs_CVE-2023-45277_5.8.6` | `cwe-022wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 62 | `jenkinsci__workflow-cps-plugin_CVE-2022-25173_2646.v6ed3b5b01ff1` | `cwe-078wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 63 | `alibaba__nacos_CVE-2021-44667_2.0.3` | `cwe-079wLLM` | `db_usable_admission_rejected` | yes | `latest-r8-94` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | fix_info_missing |
| 64 | `apache__uima-uimaj_CVE-2022-32287_3.3.0` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 65 | `apache__jspwiki_CVE-2019-10077_2.11.0.M3` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 66 | `apache__jspwiki_CVE-2019-10078_2.11.0.M3` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 67 | `apache__jspwiki_CVE-2019-10076_2.11.0.M3` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 68 | `apache__jspwiki_CVE-2019-10089_2.11.0.M4` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 69 | `DSpace__DSpace_CVE-2022-31192_5.10` | `cwe-079wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=False |
| 70 | `jmrozanec__cron-utils_CVE-2021-41269_9.1.5` | `cwe-094wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 71 | `jstachio__jstachio_CVE-2023-33962_1.0.0` | `cwe-079wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 72 | `hibernate__hibernate-validator_CVE-2019-10219_6.0.17.Final` | `cwe-079wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 73 | `spring-projects__spring-framework_CVE-2022-22965_5.2.19.RELEASE` | `cwe-094wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 74 | `apache__jspwiki_CVE-2022-46907_2.11.3` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 75 | `xwiki__xwiki-rendering_CVE-2023-32070_14.6` | `cwe-083wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 76 | `keycloak__keycloak_CVE-2014-3656_1.0.5.Final` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 77 | `xwiki__xwiki-commons_CVE-2023-29201_14.6` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 78 | `xwiki__xwiki-commons_CVE-2023-29528_14.9-rc-1` | `cwe-079wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 79 | `xwiki__xwiki-commons_CVE-2023-31126_14.10.3` | `cwe-079wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 80 | `xwiki__xwiki-commons_CVE-2023-36471_14.10.5` | `cwe-079wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 81 | `asf__commons-text_CVE-2022-42889_1.9` | `cwe-094wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=False |
| 82 | `spring-projects__spring-security_CVE-2011-2732_2.0.6.RELEASE` | `cwe-094wLLM` | `historical_codeql_not_usable` | no | `none` | `` | `not_admitted` | `not_completed` | `not_completed` | none | iris_materialization_not_selected |
| 83 | `apache__activemq_CVE-2014-3576_5.10.2` | `cwe-264wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 84 | `xwiki__xwiki-rendering_CVE-2023-37908_14.10.3` | `cwe-079wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 85 | `apache__struts_CVE-2020-17530_2.5.25` | `cwe-094wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 86 | `xerial__sqlite-jdbc_CVE-2023-32697_3.41.2.1` | `cwe-094wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 87 | `apache__rocketmq_CVE-2023-37582_4.9.6` | `cwe-094wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 88 | `ff4j__ff4j_CVE-2022-44262_1.8.13` | `cwe-094wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=False |
| 89 | `SpringSource__spring-security-oauth_CVE-2018-1260_2.3.2.RELEASE` | `cwe-094wLLM` | `codeql_first_build_not_usable` | no | `none` | `codeql_db_failed` | `admitted` | `not_completed` | `not_completed` | none | codeql_db_failed |
| 90 | `apache__activemq_CVE-2019-0222_5.15.8` | `cwe-094wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 91 | `apache__rocketmq_CVE-2023-33246_5.1.0` | `cwe-094wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 92 | `apache__activemq_CVE-2020-11998_5.15.12` | `cwe-094wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 93 | `spring-cloud__spring-cloud-gateway_CVE-2022-22947_3.0.6` | `cwe-094wLLM` | `paired_completed` | yes | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 94 | `hapifhir__org.hl7.fhir.core_CVE-2023-24057_5.6.91` | `cwe-022wLLM` | `db_usable_admission_rejected` | yes | `historical-r3-53` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | exact_source_receipt_missing;package_names_missing |
| 95 | `eclipse-ee4j__glassfish_CVE-2022-2712_6.2.5` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 96 | `eclipse__hawkbit_CVE-2020-27219_0.3.0M6` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 97 | `hapifhir__org.hl7.fhir.core_CVE-2023-28465_5.6.105` | `cwe-022wLLM` | `db_usable_admission_rejected` | yes | `historical-r3-53` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | exact_source_receipt_missing;package_names_missing |
| 98 | `asf__karaf_CVE-2022-22932_4.3.5` | `cwe-022wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 99 | `keycloak__keycloak_CVE-2022-3782_20.0.1` | `cwe-022wLLM` | `db_usable_admission_rejected` | yes | `prior_strict_or_official_codeql` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | exact_source_receipt_missing |
| 100 | `apache__incubator-dubbo_CVE-2021-30181_2.6.8` | `cwe-094wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 101 | `aws__aws-sdk-java_CVE-2022-31159_1.12.260` | `cwe-022wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 102 | `asf__cxf_CVE-2016-6812_3.0.11` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 103 | `keycloak__keycloak_CVE-2022-1274_20.0.4` | `cwe-079wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 104 | `keycloak__keycloak_CVE-2022-4137_20.0.4` | `cwe-116wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 105 | `asf__cxf_CVE-2019-17573_3.2.11` | `cwe-079wLLM` | `codeql_first_build_not_usable` | no | `none` | `build_command_discovery_failed` | `not_admitted` | `not_completed` | `not_completed` | none | build_command_discovery_failed |
| 106 | `Graylog2__graylog2-server_CVE-2023-41044_5.1.2` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 107 | `apache__dubbo_CVE-2021-30180_2.7.9` | `cwe-094wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | vanilla, posthoc | native+official_codeql completed; vanilla_hit=True; posthoc_hit=True; codeql_hit=False |
| 108 | `codecentric__spring-boot-admin_CVE-2022-46166_2.6.9` | `cwe-094wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 109 | `payara__Payara_CVE-2022-37422_5.2022.2` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 110 | `fabric8io__kubernetes-client_CVE-2021-4178_5.0.2` | `cwe-094wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 111 | `apache__dolphinscheduler_CVE-2023-49109_3.2.0` | `cwe-094wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 112 | `apache__dolphinscheduler_CVE-2023-51770_3.2.0` | `cwe-094wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 113 | `keycloak__keycloak_CVE-2022-4361_21.1.1` | `cwe-079wLLM` | `paired_completed` | yes | `historical-r3-53` | `no_safe_llm_repair` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 114 | `apache__flink_CVE-2020-17519_1.11.2` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 115 | `apache__camel_CVE-2019-0194_2.21.4` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `llm_repair_worker_failed` | `not_admitted` | `not_completed` | `not_completed` | none | llm_repair_worker_failed |
| 116 | `asf__nifi_CVE-2023-34468_1.21.0` | `cwe-094wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 117 | `asf__nifi_CVE-2023-36542_1.22.0` | `cwe-094wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `codeql_db_repaired` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 118 | `apache__nifi_CVE-2022-33140_1.16.2` | `cwe-078wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 119 | `apache__dolphinscheduler_CVE-2022-34662_2.0.9` | `cwe-022wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 120 | `apache__camel_CVE-2018-8041_2.20.3` | `cwe-022wLLM` | `historical_codeql_not_usable` | no | `none` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 121 | `jeecgboot__jeecgboot_CVE-2022-45206_3.4.3` | `cwe-089wLLM` | `db_usable_admitted_native_not_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `not_completed` | `not_completed` | none | strict native admission passed, but no completed_verified native IRIS summary in final 213 report |
| 122 | `folio-org__spring-module-core_CVE-2022-4963_2.0.0` | `cwe-089wLLM` | `paired_completed` | yes | `latest-r8-94` | `codeql_db_repaired` | `admitted` | `completed_verified` | `completed_verified` | codeql | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=True |
| 123 | `apache__kylin_CVE-2024-48944_5.0.0` | `cwe-918wLLM` | `paired_completed` | yes | `prior_strict_or_official_codeql` | `repair_attempt_failed` | `not_applicable_completed` | `completed_verified` | `completed_verified` | codeql | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=True |
| 124 | `apache__axis-axis1-java_CVE-2023-51441_1.3.0` | `cwe-918wLLM` | `paired_completed` | yes | `historical-r3-53` | `no_safe_llm_repair` | `not_applicable_completed` | `completed_verified` | `completed_verified` | none | native+official_codeql completed; vanilla_hit=False; posthoc_hit=False; codeql_hit=False |
| 125 | `apache__kafka_CVE-2025-27818_3.9.0` | `cwe-502wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 126 | `crate__crate_5.5.1_CVE-2023-51982_5.5.1` | `cwe-287wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 127 | `mapfish__mapfish-print_CVE-2020-15231_3.22.0` | `cwe-079wLLM` | `historical_codeql_not_usable` | no | `none` | `` | `not_admitted` | `not_completed` | `not_completed` | none | iris_materialization_not_selected |
| 128 | `keycloak_CVE-2025-7784_26.2.5` | `cwe-269wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 129 | `keycloak_CVE-2025-7365_26.0.12` | `cwe-346wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 130 | `opencast_CVE-2025-54380_17.5` | `cwe-200wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 131 | `jena_CVE-2025-49656_jena-5.4.0` | `cwe-022wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 132 | `reactor-netty_CVE-2025-22227_v1.2.8` | `cwe-200wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 133 | `DSpace_CVE-2025-53622_dspace-7.6.3` | `cwe-022wLLM` | `db_usable_admission_rejected` | yes | `historical-r3-53` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;exact_source_receipt_missing;package_names_missing |
| 134 | `DSpace_CVE-2025-53621_dspace-7.6.3` | `cwe-611wLLM` | `db_usable_admission_rejected` | yes | `historical-r3-53` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;exact_source_receipt_missing;package_names_missing;native_query_unsupported |
| 135 | `cxf_CVE-2025-48795_cxf-3.5.10` | `cwe-400wLLM` | `codeql_first_build_not_usable` | no | `none` | `build_command_discovery_failed` | `not_admitted` | `not_completed` | `not_completed` | none | build_command_discovery_failed |
| 136 | `jackrabbit_CVE-2025-53689_jackrabbit-2.23.1-beta` | `cwe-611wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 137 | `tomcat_CVE-2025-53506_11.0.8` | `cwe-400wLLM` | `codeql_first_build_not_usable` | no | `none` | `no_safe_initial_build_command` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_initial_build_command |
| 138 | `tomcat_CVE-2025-52520_11.0.8` | `cwe-190wLLM` | `codeql_first_build_not_usable` | no | `none` | `no_safe_initial_build_command` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_initial_build_command |
| 139 | `junit-framework_CVE-2025-53103_r5.13.1` | `cwe-312wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 140 | `graylog2-server_CVE-2025-53106_6.2.3` | `cwe-285wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 141 | `conductor_CVE-2025-26074_v3.21.12` | `cwe-078wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 142 | `jans_CVE-2025-53003_v1.7.0` | `cwe-200wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 143 | `incubator-seata_CVE-2025-32897_v2.2.0` | `cwe-502wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 144 | `allure2_CVE-2025-52888_2.34.0` | `cwe-611wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 145 | `quarkus_CVE-2025-49574_3.23.4` | `cwe-668wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 146 | `studio_CVE-2025-6384_v4.2.2` | `cwe-913wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 147 | `powsybl-core_CVE-2025-48059_v6.2.4` | `cwe-1333wLLM` | `db_usable_admission_rejected` | yes | `latest-r8-94` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;package_names_missing;native_query_unsupported |
| 148 | `powsybl-core_CVE-2025-48058_v6.7.1` | `cwe-1333wLLM` | `db_usable_admission_rejected` | yes | `latest-r8-94` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;package_names_missing;native_query_unsupported |
| 149 | `powsybl-core_CVE-2025-47771_v6.7.1` | `cwe-502wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 150 | `powsybl-core_CVE-2025-47293_v6.7.1` | `cwe-611wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 151 | `tomcat_CVE-2025-49125_11.0.7` | `cwe-288wLLM` | `codeql_first_build_not_usable` | no | `none` | `no_safe_initial_build_command` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_initial_build_command |
| 152 | `tomcat_CVE-2025-48988_11.0.7` | `cwe-770wLLM` | `codeql_first_build_not_usable` | no | `none` | `no_safe_initial_build_command` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_initial_build_command |
| 153 | `commons-fileupload_CVE-2025-48976_commons-fileupload-1.5-RC1` | `cwe-770wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 154 | `solon_CVE-2025-46096_v3.1.2` | `cwe-022wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 155 | `spring-framework_CVE-2025-41234_v6.2.7` | `cwe-113wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 156 | `geoserver_CVE-2025-30145_2.26.2` | `cwe-835wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 157 | `geoserver_CVE-2025-27505_2.26.2` | `cwe-862wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 158 | `para_CVE-2025-49009_v1.50.7` | `cwe-532wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 159 | `inlong_CVE-2025-27531_2.0.0-RC0` | `cwe-502wLLM` | `db_usable_admission_rejected` | yes | `historical-r3-53` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;exact_source_receipt_missing;package_names_missing;native_query_unsupported |
| 160 | `akka-management_CVE-2025-46548_v1.6.0-M1` | `cwe-287wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 161 | `para_CVE-2025-48955_v1.50.7` | `cwe-532wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 162 | `commons-beanutils_CVE-2025-48734_commons-beanutils-1.10.1-RC1` | `cwe-284wLLM` | `db_usable_admission_rejected` | yes | `latest-r8-94` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;package_names_missing;native_query_unsupported |
| 163 | `valtimo-backend-libraries_CVE-2025-48881_12.12.0.RELEASE` | `cwe-863wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 164 | `inlong_CVE-2025-27526_2.1.0-RC0` | `cwe-502wLLM` | `db_usable_admission_rejected` | yes | `historical-r3-53` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;exact_source_receipt_missing;package_names_missing;native_query_unsupported |
| 165 | `inlong_CVE-2025-27528_2.1.0-RC0` | `cwe-502wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 166 | `inlong_CVE-2025-27522_2.1.0-RC0` | `cwe-502wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 167 | `spring-framework_CVE-2025-22233_v6.2.6` | `cwe-020wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 168 | `cloudbees-jenkins-advisor-plugin_CVE-2025-47885_374.v194b_d4f0c8c8` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 169 | `webdrivermanager_CVE-2025-4641_webdrivermanager-6.0.1` | `cwe-611wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 170 | `iotdb_CVE-2025-26795_v1.3.3` | `cwe-200wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 171 | `iotdb_CVE-2025-26864_v1.3.3` | `cwe-200wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 172 | `jetty.project_CVE-2025-1948_jetty-12.0.16` | `cwe-400wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 173 | `console_CVE-2025-2901_v3.7.10` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `repair_attempt_failed` | `not_admitted` | `not_completed` | `not_completed` | none | repair_attempt_failed |
| 174 | `keycloak_CVE-2025-3910_26.2.1` | `cwe-287wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 175 | `keycloak_CVE-2025-3501_26.2.1` | `cwe-297wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 176 | `syntax-markdown_CVE-2025-46558_syntax-markdown-8.8` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 177 | `jpawebapi_CVE-2025-32961_v1.1.0` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 178 | `restapi_CVE-2025-32960_v7.2.6` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 179 | `cuba_CVE-2025-32959_7.2.22` | `cwe-770wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 180 | `templating-engine-plugin_CVE-2025-31722_2.5.3` | `cwe-094wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 181 | `jenkins_CVE-2025-31721_prototype-1.7` | `cwe-862wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 182 | `jenkins_CVE-2025-31720_prototype-1.7` | `cwe-862wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 183 | `simple-queue-plugin_CVE-2025-31723_simple-queue-1.4.6` | `cwe-352wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 184 | `camel_CVE-2025-30177_camel-4.10.2` | `cwe-164wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 185 | `activemq-artemis_CVE-2025-27427_2.39.0` | `cwe-863wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 186 | `netty-incubator-codec-quic_CVE-2025-29908_netty-incubator-codec-parent-quic-0.0.70.Final` | `cwe-407wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 187 | `kylin_CVE-2025-30067_kylin-5.0.1` | `cwe-094wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 188 | `spring-security_CVE-2025-22223_6.4.3` | `cwe-290wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 189 | `druid_CVE-2025-27888_druid-31.0.1-rc2` | `cwe-079wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 190 | `spring-security_CVE-2025-22228_6.3.7` | `cwe-287wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 191 | `zohoqengine-plugin_CVE-2025-30197_1.0.29.vfa_cc23396502` | `cwe-522wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 192 | `snowflake-jdbc_CVE-2025-27496_v3.23.0` | `cwe-532wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 193 | `smallrye-fault-tolerance_CVE-2025-2240_6.4.1` | `cwe-1325wLLM` | `db_usable_admission_rejected` | yes | `latest-r8-94` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;fix_info_missing;package_names_missing;native_query_unsupported |
| 194 | `keycloak_CVE-2025-1391_26.1.2` | `cwe-284wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 195 | `keycloak_CVE-2025-0604_26.1.2` | `cwe-287wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 196 | `tomcat_CVE-2025-24813_11.0.2` | `cwe-044wLLM` | `codeql_first_build_not_usable` | no | `none` | `no_safe_initial_build_command` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_initial_build_command |
| 197 | `local-s3_CVE-2025-27136_1.20` | `cwe-611wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 198 | `emissary_CVE-2025-27508_8.23.0` | `cwe-327wLLM` | `db_usable_admission_rejected` | yes | `historical-r3-53` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;fix_info_missing;exact_source_receipt_missing;package_names_missing;native_query_unsupported |
| 199 | `OpenDJ_CVE-2025-27497_4.9.2` | `cwe-835wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 200 | `solon_CVE-2025-1584_v3.0.8` | `cwe-023wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 201 | `cassandra-lucene-index_CVE-2025-26511_cassandra-4.0.16-1.0.0` | `cwe-288wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 202 | `netty_CVE-2025-25193_netty-4.1.117.Final` | `cwe-400wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 203 | `netty_CVE-2025-24970_netty-4.1.117.Final` | `cwe-020wLLM` | `db_usable_admission_rejected` | yes | `historical-r3-53` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;fix_info_missing;exact_source_receipt_missing;package_names_missing;native_query_unsupported |
| 204 | `felix-dev_CVE-2025-25247_org.osgi.compendium-1.4.0` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 205 | `cassandra_CVE-2025-23015_cassandra-5.0-alpha2` | `cwe-267wLLM` | `codeql_first_build_not_usable` | no | `none` | `no_safe_initial_build_command` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_initial_build_command |
| 206 | `s3proxy_CVE-2025-24961_s3proxy-2.5.0` | `cwe-022wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 207 | `wildfly-core_CVE-2025-23367_27.0.0.Beta7` | `cwe-284wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 208 | `djl_CVE-2025-0851_v0.30.0` | `cwe-022wLLM` | `codeql_db_not_repaired` | no | `historical-r3-53` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 209 | `snowflake-jdbc_CVE-2025-24790_v3.21.1` | `cwe-276wLLM` | `db_usable_admission_rejected` | yes | `latest-r8-94` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;fix_info_missing;package_names_missing;native_query_unsupported |
| 210 | `snowflake-jdbc_CVE-2025-24789_v3.21.1` | `cwe-426wLLM` | `db_usable_admission_rejected` | yes | `latest-r8-94` | `codeql_db_repaired` | `not_admitted` | `not_completed` | `not_completed` | none | project_info_missing_or_ambiguous;fix_info_missing;package_names_missing;native_query_unsupported |
| 211 | `oic-auth-plugin_CVE-2025-24399_4.452.v2849b_d3945fa_` | `cwe-178wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
| 212 | `cxf_CVE-2025-23184_cxf-3.5.9` | `cwe-400wLLM` | `codeql_first_build_not_usable` | no | `none` | `source_receipt_missing` | `not_admitted` | `not_completed` | `not_completed` | none | source_receipt_missing |
| 213 | `jte_CVE-2025-23026_3.1.15` | `cwe-079wLLM` | `codeql_db_not_repaired` | no | `latest-r8-94` | `no_safe_llm_repair` | `not_admitted` | `not_completed` | `not_completed` | none | no_safe_llm_repair |
