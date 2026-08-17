# VulRAG TraeX Model Comparison

| Metric | GPT-5.6-Sol (low) | DeepSeek-V4-Flash (low) |
| --- | ---: | ---: |
| Completed | 137 | 137 |
| Vulnerable verdicts | 14 | 28 |
| LLM calls | 948 | 922 |
| TraeX-reported tokens | 7941516 | 1355278 |

Common completed cases: 137

Verdict agreement: 107/137 (78.10%)

Verdict flips: 30

| Case | Baseline | Candidate |
| --- | --- | --- |
| `alfio-event__alf.io::CVE-2024-45300` | no_vulnerability_found | vulnerable |
| `alibaba__one-java-agent::CVE-2022-25842` | no_vulnerability_found | vulnerable |
| `apache__axis-axis1-java::CVE-2023-51441` | vulnerable | no_vulnerability_found |
| `apache__dubbo::CVE-2021-30181` | no_vulnerability_found | vulnerable |
| `apache__iotdb::CVE-2025-26795` | no_vulnerability_found | vulnerable |
| `apache__tomcat::CVE-2025-49125` | no_vulnerability_found | vulnerable |
| `apolloconfig__apollo::CVE-2024-43397` | no_vulnerability_found | vulnerable |
| `auth0__nextjs-auth0::CVE-2026-40155` | vulnerable | no_vulnerability_found |
| `earendil-works__pi::CVE-2026-54327` | no_vulnerability_found | vulnerable |
| `erudika__para::CVE-2025-48955` | vulnerable | no_vulnerability_found |
| `expressjs__multer::CVE-2026-3304` | no_vulnerability_found | vulnerable |
| `jeecgboot__jeecgboot::CVE-2025-14908` | vulnerable | no_vulnerability_found |
| `jeecgboot__jeecgboot::CVE-2026-5616` | no_vulnerability_found | vulnerable |
| `jenkinsci__cloudbees-jenkins-advisor-plugin::CVE-2025-47885` | vulnerable | no_vulnerability_found |
| `mantisbt__mantisbt::CVE-2026-52882` | no_vulnerability_found | vulnerable |
| `mezz__justenoughitems::CVE-2024-41565` | no_vulnerability_found | vulnerable |
| `netty__netty::CVE-2026-42577` | no_vulnerability_found | vulnerable |
| `nousresearch__hermes-agent::CVE-2026-53870` | no_vulnerability_found | vulnerable |
| `openclaw__openclaw::CVE-2026-41346` | vulnerable | no_vulnerability_found |
| `owasp__json-sanitizer::CVE-2020-13973` | no_vulnerability_found | vulnerable |
| `parse-community__parse-server::CVE-2026-34363` | no_vulnerability_found | vulnerable |
| `phoenix616__inventorygui::CVE-2025-62783` | no_vulnerability_found | vulnerable |
| `swagger-api__swagger-codegen::CVE-2021-21363` | no_vulnerability_found | vulnerable |
| `yafnet__yafnet::CVE-2026-43937` | no_vulnerability_found | vulnerable |
| `94fzb__zrlog::CVE-2020-19005` | no_vulnerability_found | vulnerable |
| `eclipse__milo::CVE-2022-25897` | no_vulnerability_found | vulnerable |
| `asynchttpclient__async-http-client::CVE-2024-53990` | no_vulnerability_found | vulnerable |
| `jeecgboot__jeecgboot::CVE-2025-14909` | vulnerable | no_vulnerability_found |
| `pgjdbc__pgjdbc::CVE-2025-49146` | vulnerable | no_vulnerability_found |
| `xwiki-contrib__oidc::CVE-2022-39387` | no_vulnerability_found | vulnerable |
