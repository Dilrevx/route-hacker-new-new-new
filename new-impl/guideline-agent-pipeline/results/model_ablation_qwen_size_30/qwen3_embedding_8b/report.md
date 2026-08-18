# Qwen3-Embedding-8B 30-Case Recall Rank Probe

Run base: `/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-30-qwen8b-20260819T041159`
Dataset: frozen Unified V2 paper-eval first 30 identities from `paper_eval_143_first30_identities.jsonl`.
Backend: `sentence-transformers direct`, model `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-8B`.
Ranking: mechanical sliding-window anchors, guideline query, full saved ranking with `--top-k 50000`.

## Summary

Metric | Value
--- | ---
Completed cases | 30/30
Full-rank hit cases | 30/30
Full-rank miss cases | 0/30
Rank p50 hits-only nearest | 236
Rank p99 hits-only nearest | 11235
Rank p50 penalized nearest | 236
Rank p99 penalized nearest | 11235
MRR all cases | 0.057730
Mean candidates/case | 11642.1

## Hit@K

K | Hit Count | Rate
---: | ---: | ---:
1 | 1 | 0.0333
3 | 1 | 0.0333
5 | 2 | 0.0667
10 | 4 | 0.1333
20 | 6 | 0.2000
30 | 7 | 0.2333
50 | 8 | 0.2667
100 | 12 | 0.4000
200 | 14 | 0.4667
500 | 17 | 0.5667
1000 | 19 | 0.6333
5000 | 26 | 0.8667
10000 | 29 | 0.9667
50000 | 30 | 1.0000

## Case Ranks

Idx | Identity | Rank | Penalized Rank | Candidates | Seconds
---: | --- | ---: | ---: | ---: | ---:
1 | `agentfront__frontmcp::GHSA-8Q49-2H5H-434X` | 1691 | 1691 | 12537 | 936.0
2 | `aiven-open__klaw::CVE-2026-25999` | 9 | 9 | 7088 | 522.6
3 | `alfio-event__alf.io::CVE-2024-45300` | 1107 | 1107 | 4561 | 330.2
4 | `alibaba__one-java-agent::CVE-2022-25842` | 111 | 111 | 244 | 20.9
5 | `apache__activemq-artemis::CVE-2025-27427` | 893 | 893 | 22852 | 1699.0
6 | `apache__activemq::CVE-2014-3576` | 28 | 28 | 13837 | 1014.8
7 | `apache__activemq::CVE-2020-11998` | 1181 | 1181 | 16951 | 1274.4
8 | `apache__axis-axis1-java::CVE-2023-51441` | 1324 | 1324 | 6173 | 456.3
9 | `apache__camel::CVE-2026-53913` | 36 | 36 | 50000 | 3896.0
10 | `apache__commons-beanutils::CVE-2025-48734` | 11 | 11 | 1347 | 103.1
11 | `apache__commons-fileupload::CVE-2025-48976` | 277 | 277 | 419 | 33.5
12 | `apache__commons-io::CVE-2021-29425` | 111 | 111 | 1375 | 102.2
13 | `apache__commons-text::CVE-2022-42889` | 53 | 53 | 1155 | 88.5
14 | `apache__dubbo::CVE-2021-30181` | 254 | 254 | 3837 | 295.8
15 | `apache__felix-dev::CVE-2025-25247` | 7197 | 7197 | 16783 | 1234.1
16 | `apache__incubator-seata::CVE-2025-32897` | 9 | 9 | 6793 | 511.0
17 | `apache__inlong::CVE-2025-27531` | 1 | 1 | 19871 | 1488.4
18 | `apache__iotdb::CVE-2025-26795` | 81 | 81 | 24352 | 1785.6
19 | `apache__iotdb::CVE-2025-26864` | 81 | 81 | 24352 | 1854.1
20 | `apache__jackrabbit::CVE-2025-53689` | 7159 | 7159 | 14077 | 1072.0
21 | `apache__myfaces::CVE-2011-4367` | 236 | 236 | 5979 | 435.3
22 | `apache__sling-org-apache-sling-servlets-resolver::CVE-2024-23673` | 5 | 5 | 290 | 25.1
23 | `apache__sling-org-apache-sling-xss::CVE-2016-5394` | 16 | 16 | 215 | 18.7
24 | `apache__tika::CVE-2018-11762` | 648 | 648 | 4611 | 344.3
25 | `apache__tomcat::CVE-2025-24813` | 2380 | 2380 | 16918 | 1262.9
26 | `apache__tomcat::CVE-2025-48988` | 7692 | 7692 | 17221 | 1332.3
27 | `apache__tomcat::CVE-2025-49125` | 1765 | 1765 | 17519 | 1325.7
28 | `apache__tomcat::CVE-2025-52520` | 11235 | 11235 | 18254 | 1334.4
29 | `apache__tomcat::CVE-2025-53506` | 2387 | 2387 | 17518 | 1338.2
30 | `api-platform__core::CVE-2026-49858` | 85 | 85 | 2133 | 157.6
