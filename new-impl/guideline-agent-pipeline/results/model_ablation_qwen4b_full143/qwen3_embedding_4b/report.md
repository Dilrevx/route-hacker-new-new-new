# Qwen3-Embedding-4B Full 143-Case Unified V2 Recall Rank Probe

Run base: `/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-143-qwen4b-20260819T052314`
Dataset: frozen Unified V2 paper-eval 143 identities from paper_eval_143_identities.jsonl.
Backend: `sentence-transformers direct`, model `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-4B`.
Ranking: mechanical sliding-window anchors, guideline query, full saved ranking with `--top-k 50000`.

## Summary

Metric | Value
--- | ---
Completed cases | 143/143
Full-rank hit cases | 139/143
Full-rank miss cases | 4/143
Rank p50 hits-only nearest | 166
Rank p99 hits-only nearest | 12100
Rank p50 penalized nearest | 166
Rank p99 penalized nearest | 13039
MRR all cases | 0.050733
Mean candidates/case | 7663.1

## Hit@K

K | Hit Count | Rate
---: | ---: | ---:
1 | 3 | 0.0210
3 | 6 | 0.0420
5 | 8 | 0.0559
10 | 15 | 0.1049
20 | 23 | 0.1608
30 | 30 | 0.2098
50 | 37 | 0.2587
100 | 55 | 0.3846
200 | 74 | 0.5175
500 | 94 | 0.6573
1000 | 109 | 0.7622
5000 | 132 | 0.9231
10000 | 137 | 0.9580
50000 | 139 | 0.9720

## Case Ranks

Idx | Identity | Rank | Penalized Rank | Candidates | Seconds
---: | --- | ---: | ---: | ---: | ---:
1 | `agentfront__frontmcp::GHSA-8Q49-2H5H-434X` | 2850 | 2850 | 12537 | 548.4
2 | `aiven-open__klaw::CVE-2026-25999` | 67 | 67 | 7088 | 312.3
3 | `alfio-event__alf.io::CVE-2024-45300` | 1204 | 1204 | 4561 | 213.9
4 | `alibaba__one-java-agent::CVE-2022-25842` | 81 | 81 | 244 | 13.9
5 | `apache__activemq-artemis::CVE-2025-27427` | 1798 | 1798 | 22852 | 1072.8
6 | `apache__activemq::CVE-2014-3576` | 2 | 2 | 13837 | 629.5
7 | `apache__activemq::CVE-2020-11998` | 4546 | 4546 | 16951 | 759.1
8 | `apache__axis-axis1-java::CVE-2023-51441` | 4033 | 4033 | 6173 | 290.5
9 | `apache__camel::CVE-2026-53913` | 271 | 271 | 50000 | 2246.2
10 | `apache__commons-beanutils::CVE-2025-48734` | 61 | 61 | 1347 | 63.6
11 | `apache__commons-fileupload::CVE-2025-48976` | 310 | 310 | 419 | 22.5
12 | `apache__commons-io::CVE-2021-29425` | 173 | 173 | 1375 | 64.8
13 | `apache__commons-text::CVE-2022-42889` | 103 | 103 | 1155 | 55.0
14 | `apache__dubbo::CVE-2021-30181` | 51 | 51 | 3837 | 176.1
15 | `apache__felix-dev::CVE-2025-25247` | 2556 | 2556 | 16783 | 756.5
16 | `apache__incubator-seata::CVE-2025-32897` | 352 | 352 | 6793 | 313.5
17 | `apache__inlong::CVE-2025-27531` | 20 | 20 | 19871 | 925.4
18 | `apache__iotdb::CVE-2025-26795` | 166 | 166 | 24352 | 1092.1
19 | `apache__iotdb::CVE-2025-26864` | 166 | 166 | 24352 | 1111.1
20 | `apache__jackrabbit::CVE-2025-53689` | 6112 | 6112 | 14077 | 651.3
21 | `apache__myfaces::CVE-2011-4367` | 844 | 844 | 5979 | 271.2
22 | `apache__sling-org-apache-sling-servlets-resolver::CVE-2024-23673` | 38 | 38 | 290 | 16.4
23 | `apache__sling-org-apache-sling-xss::CVE-2016-5394` | 17 | 17 | 215 | 12.6
24 | `apache__tika::CVE-2018-11762` | 79 | 79 | 4611 | 217.1
25 | `apache__tomcat::CVE-2025-24813` | 801 | 801 | 16918 | 758.1
26 | `apache__tomcat::CVE-2025-48988` | 1869 | 1869 | 17221 | 766.3
27 | `apache__tomcat::CVE-2025-49125` | 823 | 823 | 17519 | 771.3
28 | `apache__tomcat::CVE-2025-52520` | 8308 | 8308 | 18254 | 842.9
29 | `apache__tomcat::CVE-2025-53506` | 2265 | 2265 | 17518 | 817.3
30 | `api-platform__core::CVE-2026-49858` | 78 | 78 | 2133 | 97.6
31 | `apolloconfig__apollo::CVE-2024-43397` | 23 | 23 | 1833 | 85.1
32 | `arcadedata__arcadedb::CVE-2026-44221` | 39 | 39 | 16326 | 724.4
33 | `auth0__nextjs-auth0::CVE-2026-40155` | 84 | 84 | 2332 | 104.5
34 | `bonigarcia__webdrivermanager::CVE-2025-4641` | 36 | 36 | 359 | 19.9
35 | `chartbrew__chartbrew::CVE-2026-32252` | 148 | 148 | 2837 | 134.4
36 | `cloudreve__cloudreve::CVE-2026-55499` | 646 | 646 | 3833 | 174.0
37 | `code16__sharp::CVE-2026-53634` | 564 | 564 | 899 | 40.4
38 | `coder__coder::CVE-2026-55435` | 5073 | 5073 | 30860 | 1379.8
39 | `conductor-oss__conductor::CVE-2025-26074` | 80 | 80 | 4188 | 186.9
40 | `corewcf__corewcf::CVE-2026-54778` | MISS | 391 | 390 | 23.9
41 | `craftcms__cms::CVE-2026-50279` | 413 | 413 | 8518 | 393.0
42 | `cuba-platform__cuba::CVE-2025-32959` | 745 | 745 | 14451 | 651.8
43 | `cyberjunky__python-garminconnect::CVE-2026-54447` | 347 | 347 | 596 | 28.6
44 | `dromara__hutool::CVE-2018-17297` | 2420 | 2420 | 3199 | 145.0
45 | `dspace__dspace::CVE-2025-53621` | 30 | 30 | 15450 | 676.6
46 | `dspace__dspace::CVE-2025-53622` | 443 | 443 | 14929 | 686.0
47 | `earendil-works__pi::CVE-2026-54327` | 2064 | 2064 | 4596 | 214.0
48 | `eclipse-californium__californium::CVE-2022-39368` | 489 | 489 | 4577 | 209.5
49 | `envoyproxy__gateway::CVE-2026-53715` | 2647 | 2647 | 16204 | 720.5
50 | `erudika__para::CVE-2025-48955` | 74 | 74 | 1154 | 53.2
51 | `erudika__para::CVE-2025-49009` | 150 | 150 | 1154 | 53.2
52 | `ethyca__fides::CVE-2026-42303` | 589 | 589 | 18387 | 830.1
53 | `expressjs__multer::CVE-2026-3304` | 32 | 32 | 64 | 6.8
54 | `filamentphp__filament::CVE-2026-48505` | 2141 | 2141 | 9915 | 424.5
55 | `forgekeep__nebula-mesh::GHSA-7RX3-5WX3-5V76` | 152 | 152 | 1463 | 67.3
56 | `free5gc__bsf::CVE-2026-44318` | 88 | 88 | 113 | 7.8
57 | `getkin__kin-openapi::GHSA-R277-6W6Q-XMQW` | 554 | 554 | 1808 | 84.0
58 | `graylog2__graylog2-server::CVE-2025-53106` | 226 | 226 | 19039 | 839.5
59 | `hal__console::CVE-2025-2901` | 100 | 100 | 4443 | 209.7
60 | `jandedobbeleer__oh-my-posh::GHSA-6XJ8-QV9J-XCJQ` | 339 | 339 | 1755 | 83.4
61 | `jeecgboot__jeecgboot::CVE-2025-14908` | 1091 | 1091 | 6551 | 292.4
62 | `jeecgboot__jeecgboot::CVE-2026-5616` | 4338 | 4338 | 7342 | 330.1
63 | `jenkinsci__cloudbees-jenkins-advisor-plugin::CVE-2025-47885` | 8 | 8 | 90 | 7.6
64 | `jenkinsci__oic-auth-plugin::CVE-2025-24399` | 66 | 66 | 179 | 12.5
65 | `jeremylong__dependencycheck::CVE-2018-12036` | 463 | 463 | 1950 | 98.8
66 | `junit-team__junit-framework::CVE-2025-53103` | 129 | 129 | 4864 | 223.3
67 | `keycloak__keycloak::CVE-2022-4361` | 688 | 688 | 25428 | 1120.0
68 | `mantisbt__mantisbt::CVE-2026-52882` | 235 | 235 | 4507 | 200.2
69 | `mezz__justenoughitems::CVE-2024-41565` | 5 | 5 | 1251 | 55.0
70 | `microsoft__prompty::GHSA-W28W-GP39-M4P6` | 333 | 333 | 4199 | 196.8
71 | `modelcontextprotocol__python-sdk::CVE-2026-52869` | 632 | 632 | 1550 | 73.9
72 | `nesquena__hermes-webui::CVE-2026-6830` | 203 | 203 | 588 | 30.0
73 | `netty__netty::CVE-2026-42577` | 4736 | 4736 | 15217 | 678.7
74 | `nousresearch__hermes-agent::CVE-2026-53870` | 3594 | 3594 | 23978 | 1118.4
75 | `nyariv__sandboxjs::CVE-2026-32723` | 24 | 24 | 582 | 28.1
76 | `okta__okta-sdk-java::CVE-2025-66033` | 155 | 155 | 281 | 17.0
77 | `olivetin__olivetin::CVE-2026-48708` | 371 | 371 | 589 | 30.3
78 | `openclaw__openclaw::CVE-2026-32018` | 3215 | 3215 | 16072 | 745.5
79 | `openclaw__openclaw::CVE-2026-41346` | 5390 | 5390 | 40762 | 1818.2
80 | `openremote__openremote::CVE-2026-49439` | 17 | 17 | 5659 | 270.9
81 | `owasp__json-sanitizer::CVE-2020-13973` | 1 | 1 | 60 | 10.6
82 | `parse-community__parse-server::CVE-2026-34363` | 20 | 20 | 3732 | 174.6
83 | `pheditor__pheditor::GHSA-F25V-X6VR-962G` | 10 | 10 | 58 | 5.9
84 | `phoenix616__inventorygui::CVE-2025-62782` | 15 | 15 | 86 | 6.9
85 | `phoenix616__inventorygui::CVE-2025-62783` | 31 | 31 | 81 | 6.8
86 | `phoenix616__inventorygui::CVE-2025-62784` | 5 | 5 | 94 | 9.5
87 | `poweradmin__poweradmin::GHSA-H4HF-V6W5-897X` | 311 | 311 | 2772 | 133.0
88 | `quarkusio__quarkus::CVE-2025-49574` | 13039 | 13039 | 38444 | 1705.3
89 | `remix-run__react-router::CVE-2026-53668` | 3632 | 3632 | 5095 | 236.4
90 | `sanluan__publiccms::CVE-2026-2010` | 2006 | 2006 | 5778 | 273.7
91 | `shedaniel__roughlyenoughitems::CVE-2024-42698` | 141 | 141 | 1704 | 77.5
92 | `shopizer-ecommerce__shopizer::CVE-2020-11007` | 657 | 657 | 4704 | 217.7
93 | `shopperlabs__shopper::CVE-2026-47741` | 752 | 752 | 2052 | 87.2
94 | `simplesamlphp__simplesamlphp-module-casserver::CVE-2025-65954` | 6 | 6 | 83 | 7.0
95 | `sooperset__mcp-atlassian::CVE-2026-27826` | 1 | 1 | 1826 | 87.3
96 | `spectolabs__hoverfly::CVE-2026-50013` | 116 | 116 | 1556 | 76.7
97 | `spring-cloud__spring-cloud-config::CVE-2020-5405` | 36 | 36 | 702 | 34.0
98 | `spring-cloud__spring-cloud-gateway::CVE-2022-22947` | 207 | 207 | 944 | 47.4
99 | `square__retrofit::CVE-2018-1000850` | 18 | 18 | 666 | 36.8
100 | `steeltoeoss__steeltoe::CVE-2026-50267` | MISS | 29 | 28 | 7.4
101 | `steipete__summarize::CVE-2026-45245` | 41 | 41 | 3274 | 153.7
102 | `steve-community__steve::CVE-2026-28230` | 127 | 127 | 880 | 44.7
103 | `subzeroid__aiograpi::CVE-2026-47157` | 265 | 265 | 783 | 37.6
104 | `sveltejs__kit::CVE-2026-40074` | 24 | 24 | 2663 | 106.1
105 | `swagger-api__swagger-codegen::CVE-2021-21363` | 2938 | 2938 | 17843 | 769.7
106 | `swagger-api__swagger-codegen::CVE-2021-21364` | MISS | 17844 | 17843 | 812.1
107 | `sylius__sylius::CVE-2026-53637` | 6760 | 6760 | 11114 | 487.4
108 | `useplunk__plunk::CVE-2026-32096` | 514 | 514 | 2105 | 98.4
109 | `vert-x3__vertx-web::CVE-2018-12542` | 120 | 120 | 2135 | 94.6
110 | `vert-x3__vertx-web::CVE-2019-17640` | 67 | 67 | 2393 | 108.3
111 | `viewcomponent__view_component::CVE-2026-54497` | 137 | 137 | 645 | 25.4
112 | `wakujs__waku::CVE-2026-49456` | 51 | 51 | 1593 | 66.0
113 | `weld__core::CVE-2014-8122` | 14 | 14 | 5735 | 249.5
114 | `wevm__mppx::CVE-2026-34209` | 298 | 298 | 1138 | 54.1
115 | `wildfly-security__soteria::CVE-2020-1732` | 80 | 80 | 427 | 22.6
116 | `workos__authkit-session::CVE-2026-42565` | 25 | 25 | 170 | 10.5
117 | `xuxueli__xxl-job::CVE-2020-29204` | 158 | 158 | 907 | 43.6
118 | `xwiki-contrib__syntax-markdown::CVE-2025-46558` | 8 | 8 | 114 | 8.5
119 | `xwiki__xwiki-commons::CVE-2024-31996` | 134 | 134 | 4878 | 225.1
120 | `xwiki__xwiki-rendering::CVE-2025-66474` | 25 | 25 | 2254 | 105.3
121 | `yafnet__yafnet::CVE-2026-43937` | MISS | 721 | 720 | 42.2
122 | `googleapis__google-oauth-java-client::CVE-2020-7692` | 8 | 8 | 406 | 20.2
123 | `94fzb__zrlog::CVE-2020-19005` | 7 | 7 | 674 | 31.9
124 | `xwiki__xwiki-platform::CVE-2022-23617` | 183 | 183 | 30087 | 1401.6
125 | `eclipse__milo::CVE-2022-25897` | 861 | 861 | 5687 | 261.1
126 | `authguard__authguard::CVE-2021-45890` | 8 | 8 | 770 | 38.0
127 | `pilinux__gorest::CVE-2026-48154` | 61 | 61 | 535 | 26.2
128 | `xwiki__xwiki-platform::CVE-2022-23615` | 1 | 1 | 29963 | 1347.3
129 | `anthropics__anthropic-sdk-python::CVE-2026-34450` | 16 | 16 | 1601 | 67.2
130 | `asynchttpclient__async-http-client::CVE-2024-53990` | 56 | 56 | 1093 | 51.1
131 | `jeecgboot__jeecgboot::CVE-2025-14909` | 1360 | 1360 | 6551 | 303.9
132 | `jupyterhub__oauthenticator::CVE-2026-33175` | 74 | 74 | 238 | 14.3
133 | `netty__netty::CVE-2021-21290` | 2 | 2 | 10978 | 480.3
134 | `openclaw__openclaw::CVE-2026-33572` | 409 | 409 | 16072 | 708.3
135 | `parisneo__lollms::CVE-2026-0558` | 526 | 526 | 1013 | 49.0
136 | `pgjdbc__pgjdbc::CVE-2025-49146` | 21 | 21 | 3030 | 134.9
137 | `wevm__mppx::CVE-2026-34210` | 162 | 162 | 1139 | 56.8
138 | `xwiki-contrib__oidc::CVE-2022-39387` | 2 | 2 | 188 | 12.2
139 | `openclaw__openclaw::CVE-2026-28471` | 4346 | 4346 | 13184 | 579.5
140 | `openclaw__openclaw::CVE-2026-41366` | 1038 | 1038 | 39882 | 1765.4
141 | `xwiki__xwiki_platform::CVE-2022-23621` | 12100 | 12100 | 30736 | 1360.6
142 | `xwiki__xwiki_platform::CVE-2022-36090` | 293 | 293 | 31648 | 1415.9
143 | `parse-community__parse-server::CVE-2026-33409` | 192 | 192 | 3690 | 170.1
