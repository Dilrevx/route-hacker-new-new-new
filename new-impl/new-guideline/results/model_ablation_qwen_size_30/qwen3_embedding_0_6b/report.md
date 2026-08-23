# Qwen3-Embedding-0.6B 30-Case Recall Rank Probe

Run base: `/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-30-20260818T185429`
Dataset: frozen Unified V2 paper-eval first 30 identities from `paper_eval_143_first30_identities.jsonl`.
Backend: direct `sentence-transformers`, model `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-0.6B`, one worker per GPU on cuda:2..7.
Ranking: mechanical sliding-window anchors, guideline query, full saved ranking with `--top-k 50000`.

## Summary

Metric | Value
--- | ---
Completed cases | 30/30
Full-rank hit cases | 30/30
Full-rank miss cases | 0/30
Rank p50 hits-only nearest | 707
Rank p99 hits-only nearest | 13896
Rank p50 penalized nearest | 707
Rank p99 penalized nearest | 13896
MRR all cases | 0.030183
Mean candidates/case | 11642.1

## Hit@K

K | Hit Count | Rate
---: | ---: | ---:
1 | 0 | 0.0000
3 | 1 | 0.0333
5 | 2 | 0.0667
10 | 2 | 0.0667
20 | 3 | 0.1000
30 | 3 | 0.1000
50 | 3 | 0.1000
100 | 5 | 0.1667
200 | 9 | 0.3000
500 | 13 | 0.4333
1000 | 16 | 0.5333
5000 | 23 | 0.7667
10000 | 27 | 0.9000
50000 | 30 | 1.0000

## Case Ranks

Idx | Identity | Rank | Penalized Rank | Candidates | Seconds
---: | --- | ---: | ---: | ---: | ---:
1 | `agentfront__frontmcp::GHSA-8Q49-2H5H-434X` | 7610 | 7610 | 12537 | 180.3
2 | `aiven-open__klaw::CVE-2026-25999` | 370 | 370 | 7088 | 115.1
3 | `alfio-event__alf.io::CVE-2024-45300` | 354 | 354 | 4561 | 68.7
4 | `alibaba__one-java-agent::CVE-2022-25842` | 128 | 128 | 244 | 6.4
5 | `apache__activemq-artemis::CVE-2025-27427` | 2102 | 2102 | 22852 | 315.7
6 | `apache__activemq::CVE-2014-3576` | 2 | 2 | 13837 | 189.7
7 | `apache__activemq::CVE-2020-11998` | 156 | 156 | 16951 | 231.3
8 | `apache__axis-axis1-java::CVE-2023-51441` | 5156 | 5156 | 6173 | 89.4
9 | `apache__camel::CVE-2026-53913` | 3633 | 3633 | 50000 | 719.5
10 | `apache__commons-beanutils::CVE-2025-48734` | 66 | 66 | 1347 | 21.1
11 | `apache__commons-fileupload::CVE-2025-48976` | 230 | 230 | 419 | 10.0
12 | `apache__commons-io::CVE-2021-29425` | 100 | 100 | 1375 | 20.9
13 | `apache__commons-text::CVE-2022-42889` | 451 | 451 | 1155 | 18.3
14 | `apache__dubbo::CVE-2021-30181` | 1060 | 1060 | 3837 | 58.1
15 | `apache__felix-dev::CVE-2025-25247` | 12038 | 12038 | 16783 | 228.2
16 | `apache__incubator-seata::CVE-2025-32897` | 1538 | 1538 | 6793 | 102.1
17 | `apache__inlong::CVE-2025-27531` | 182 | 182 | 19871 | 273.1
18 | `apache__iotdb::CVE-2025-26795` | 707 | 707 | 24352 | 317.7
19 | `apache__iotdb::CVE-2025-26864` | 707 | 707 | 24352 | 337.6
20 | `apache__jackrabbit::CVE-2025-53689` | 13896 | 13896 | 14077 | 202.4
21 | `apache__myfaces::CVE-2011-4367` | 2378 | 2378 | 5979 | 84.7
22 | `apache__sling-org-apache-sling-servlets-resolver::CVE-2024-23673` | 12 | 12 | 290 | 7.4
23 | `apache__sling-org-apache-sling-xss::CVE-2016-5394` | 4 | 4 | 215 | 6.9
24 | `apache__tika::CVE-2018-11762` | 568 | 568 | 4611 | 73.5
25 | `apache__tomcat::CVE-2025-24813` | 2583 | 2583 | 16918 | 253.0
26 | `apache__tomcat::CVE-2025-48988` | 8456 | 8456 | 17221 | 235.1
27 | `apache__tomcat::CVE-2025-49125` | 2756 | 2756 | 17519 | 243.6
28 | `apache__tomcat::CVE-2025-52520` | 13874 | 13874 | 18254 | 253.9
29 | `apache__tomcat::CVE-2025-53506` | 5998 | 5998 | 17518 | 250.2
30 | `api-platform__core::CVE-2026-49858` | 160 | 160 | 2133 | 31.7
