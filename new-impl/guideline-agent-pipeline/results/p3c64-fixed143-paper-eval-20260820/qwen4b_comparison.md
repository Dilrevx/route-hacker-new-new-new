# HCVR Recall Rank Comparison

- Left: `p3c64-fixed-paper-eval-143` (143 rows)
- Right: `qwen3-embedding-4b-frozen-paper-eval` (143 rows)
- Common identities: 143
- Same identity set: True
- Same identity order: True
- Mismatch allowed: False

## Metrics On Common Identities

| Metric | Left | Right | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 45/143 | 30/143 | 15 |
| Hit@50 | 56/143 | 37/143 | 19 |
| Hit@100 | 73/143 | 55/143 | 18 |
| Hit@200 | 84/143 | 74/143 | 10 |
| Hit@300 | 91/143 | 82/143 | 9 |
| Hit@500 | 103/143 | 94/143 | 9 |
| MRR | 0.088528 | 0.050733 | 0.037794 |

## Primary Budget Crossing: Top-200

- Both hit: 62
- Left-only hit: 22
- Right-only hit: 12
- Both miss: 47

### Left-Only Hits

- `envoyproxy__gateway::CVE-2026-53715` left=2 right=2647 type=`toctou_check_use_race`
- `jeecgboot__jeecgboot::CVE-2025-14909` left=2 right=1360 type=`authorization_bypass`
- `cyberjunky__python-garminconnect::CVE-2026-54447` left=3 right=347 type=`file_permission_temp_resource`
- `getkin__kin-openapi::GHSA-R277-6W6Q-XMQW` left=3 right=554 type=`m9_wave4`
- `earendil-works__pi::CVE-2026-54327` left=6 right=2064 type=`m9_expansion`
- `filamentphp__filament::CVE-2026-48505` left=10 right=2141 type=`business_state_precondition`
- `coder__coder::CVE-2026-55435` left=15 right=5073 type=`m9_expansion`
- `jandedobbeleer__oh-my-posh::GHSA-6XJ8-QV9J-XCJQ` left=35 right=339 type=`m9_wave4`
- `nesquena__hermes-webui::CVE-2026-6830` left=43 right=203 type=`concurrent_object_lifecycle`
- `cuba-platform__cuba::CVE-2025-32959` left=52 right=745 type=`iris`
- `apache__commons-fileupload::CVE-2025-48976` left=64 right=310 type=`iris`
- `graylog2__graylog2-server::CVE-2025-53106` left=72 right=226 type=`authorization_bypass`
- `apache__incubator-seata::CVE-2025-32897` left=74 right=352 type=`iris`
- `code16__sharp::CVE-2026-53634` left=74 right=564 type=`m9_expansion`
- `subzeroid__aiograpi::CVE-2026-47157` left=82 right=265 type=`ssrf`
- `jeremylong__dependencycheck::CVE-2018-12036` left=93 right=463 type=`iris`
- `useplunk__plunk::CVE-2026-32096` left=106 right=514 type=`ssrf`
- `apache__activemq::CVE-2020-11998` left=109 right=4546 type=`iris`
- `ethyca__fides::CVE-2026-42303` left=111 right=589 type=`business_state_precondition`
- `modelcontextprotocol__python-sdk::CVE-2026-52869` left=115 right=632 type=`authorization_bypass`
- `spring-cloud__spring-cloud-gateway::CVE-2022-22947` left=130 right=207 type=`iris`
- `eclipse__milo::CVE-2022-25897` left=142 right=861 type=`business_state_precondition`

### Right-Only Hits

- `openremote__openremote::CVE-2026-49439` right=17 left=434 type=`authorization_bypass`
- `apache__inlong::CVE-2025-27531` right=20 left=623 type=`iris`
- `parse-community__parse-server::CVE-2026-34363` right=20 left=367 type=`toctou_check_use_race`
- `apolloconfig__apollo::CVE-2024-43397` right=23 left=554 type=`authorization_bypass`
- `xwiki__xwiki-rendering::CVE-2025-66474` right=25 left=248 type=`template_expression_injection`
- `apache__dubbo::CVE-2021-30181` right=51 left=1100 type=`iris`
- `api-platform__core::CVE-2026-49858` right=78 left=737 type=`concurrent_object_lifecycle`
- `conductor-oss__conductor::CVE-2025-26074` right=80 left=1321 type=`iris`
- `steve-community__steve::CVE-2026-28230` right=127 left=355 type=`authorization_bypass`
- `chartbrew__chartbrew::CVE-2026-32252` right=148 left=722 type=`authorization_bypass`
- `wevm__mppx::CVE-2026-34210` right=162 left=409 type=`business_state_precondition`
- `xwiki__xwiki-platform::CVE-2022-23617` right=183 left=1013 type=`authorization_bypass`
