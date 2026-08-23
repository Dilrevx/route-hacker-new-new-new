# HCVR Recall Rank Comparison

- Left: `p3c64-current-accepted-first143` (143 rows)
- Right: `qwen3-embedding-4b-frozen-paper-eval` (143 rows)
- Common identities: 38
- Same identity set: False
- Same identity order: False
- Mismatch allowed: True
- Left-only identities: 105
- Right-only identities: 105

## Metrics On Common Identities

| Metric | Left | Right | Delta |
| --- | ---: | ---: | ---: |
| Hit@30 | 12/38 | 7/38 | 5 |
| Hit@50 | 15/38 | 10/38 | 5 |
| Hit@100 | 19/38 | 18/38 | 1 |
| Hit@200 | 21/38 | 22/38 | -1 |
| Hit@300 | 21/38 | 23/38 | -2 |
| Hit@500 | 21/38 | 25/38 | -4 |
| MRR | 0.071632 | 0.032255 | 0.039376 |

## Primary Budget Crossing: Top-200

- Both hit: 18
- Left-only hit: 3
- Right-only hit: 4
- Both miss: 13

### Left-Only Hits

- `apache__commons-fileupload::CVE-2025-48976` left=64 right=310 type=`iris`
- `apache__incubator-seata::CVE-2025-32897` left=74 right=352 type=`iris`
- `apache__activemq::CVE-2020-11998` left=109 right=4546 type=`iris`

### Right-Only Hits

- `apache__inlong::CVE-2025-27531` right=20 left=None type=`iris`
- `apolloconfig__apollo::CVE-2024-43397` right=23 left=None type=`authorization_bypass`
- `apache__dubbo::CVE-2021-30181` right=51 left=None type=`iris`
- `api-platform__core::CVE-2026-49858` right=78 left=None type=`concurrent_object_lifecycle`

## Identity Mismatch Samples

Left-only sample:
- `4ra1n__super-xray::CVE-2022-41958`
- `94fzb__zrlog-plugin-backup-sql-file::CVE-2024-57669`
- `abersheeran__rpc.py::CVE-2022-35411`
- `aces__loris::CVE-2026-39985`
- `adonisjs__http-server::CVE-2026-40255`
- `airsonic__airsonic::CVE-2019-10908`
- `akka__akka-management::CVE-2025-46548`
- `alibaba__nacos::CVE-2021-44667`
- `alkacon__opencms-core::CVE-2023-31544`
- `allure-framework__allure2::CVE-2025-52888`
- `angular__angular-cli::CVE-2026-27738`
- `ansible__ansible-runner::CVE-2021-3701`
- `apache__activemq::CVE-2019-0222`
- `apache__camel::CVE-2018-8041`
- `apache__camel::CVE-2019-0194`
- `apache__camel::CVE-2025-30177`
- `apache__cassandra::CVE-2025-23015`
- `apache__cxf-fediz::CVE-2018-8038`
- `apache__cxf::CVE-2016-6812`
- `apache__cxf::CVE-2019-17573`

Right-only sample:
- `chartbrew__chartbrew::CVE-2026-32252`
- `cloudreve__cloudreve::CVE-2026-55499`
- `code16__sharp::CVE-2026-53634`
- `coder__coder::CVE-2026-55435`
- `conductor-oss__conductor::CVE-2025-26074`
- `corewcf__corewcf::CVE-2026-54778`
- `craftcms__cms::CVE-2026-50279`
- `cuba-platform__cuba::CVE-2025-32959`
- `cyberjunky__python-garminconnect::CVE-2026-54447`
- `dromara__hutool::CVE-2018-17297`
- `dspace__dspace::CVE-2025-53621`
- `dspace__dspace::CVE-2025-53622`
- `earendil-works__pi::CVE-2026-54327`
- `eclipse-californium__californium::CVE-2022-39368`
- `eclipse__milo::CVE-2022-25897`
- `envoyproxy__gateway::CVE-2026-53715`
- `erudika__para::CVE-2025-48955`
- `erudika__para::CVE-2025-49009`
- `ethyca__fides::CVE-2026-42303`
- `expressjs__multer::CVE-2026-3304`
