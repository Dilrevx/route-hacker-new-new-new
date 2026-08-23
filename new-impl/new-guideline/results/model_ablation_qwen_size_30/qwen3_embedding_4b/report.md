# Qwen3-Embedding-4B 30-Case Recall Rank Probe

Run base: `/data/lhq/workspace/hcvr-embedding-qwen-size-runs/run-30-qwen4b-20260818T213016`
Dataset: frozen Unified V2 paper-eval first 30 identities from `paper_eval_143_first30_identities.jsonl`.
Backend: `sentence-transformers direct`, model `/data/lhq/workspace/hcvr-embedding-service/models/Qwen3-Embedding-4B`.
Ranking: mechanical sliding-window anchors, guideline query, full saved ranking with `--top-k 50000`.

## Summary

Metric | Value
--- | ---
Completed cases | 30/30
Full-rank hit cases | 30/30
Full-rank miss cases | 0/30
Rank p50 hits-only nearest | 271
Rank p99 hits-only nearest | 8313
Rank p50 penalized nearest | 271
Rank p99 penalized nearest | 8313
MRR all cases | 0.025628
Mean candidates/case | 11642.1

## Hit@K

K | Hit Count | Rate
---: | ---: | ---:
1 | 0 | 0.0000
3 | 1 | 0.0333
5 | 1 | 0.0333
10 | 1 | 0.0333
20 | 3 | 0.1000
30 | 3 | 0.1000
50 | 4 | 0.1333
100 | 10 | 0.3333
200 | 14 | 0.4667
500 | 17 | 0.5667
1000 | 20 | 0.6667
5000 | 28 | 0.9333
10000 | 30 | 1.0000
50000 | 30 | 1.0000

## Case Ranks

Idx | Identity | Rank | Penalized Rank | Candidates | Seconds
---: | --- | ---: | ---: | ---: | ---:
1 | `agentfront__frontmcp::GHSA-8Q49-2H5H-434X` | 2849 | 2849 | 12537 | 568.3
2 | `aiven-open__klaw::CVE-2026-25999` | 68 | 68 | 7088 | 316.5
3 | `alfio-event__alf.io::CVE-2024-45300` | 1204 | 1204 | 4561 | 200.2
4 | `alibaba__one-java-agent::CVE-2022-25842` | 82 | 82 | 244 | 13.5
5 | `apache__activemq-artemis::CVE-2025-27427` | 1801 | 1801 | 22852 | 1019.6
6 | `apache__activemq::CVE-2014-3576` | 2 | 2 | 13837 | 638.5
7 | `apache__activemq::CVE-2020-11998` | 4550 | 4550 | 16951 | 773.3
8 | `apache__axis-axis1-java::CVE-2023-51441` | 4029 | 4029 | 6173 | 277.3
9 | `apache__camel::CVE-2026-53913` | 271 | 271 | 50000 | 2206.9
10 | `apache__commons-beanutils::CVE-2025-48734` | 61 | 61 | 1347 | 62.5
11 | `apache__commons-fileupload::CVE-2025-48976` | 312 | 312 | 419 | 20.9
12 | `apache__commons-io::CVE-2021-29425` | 173 | 173 | 1375 | 62.6
13 | `apache__commons-text::CVE-2022-42889` | 104 | 104 | 1155 | 53.3
14 | `apache__dubbo::CVE-2021-30181` | 51 | 51 | 3837 | 171.0
15 | `apache__felix-dev::CVE-2025-25247` | 2556 | 2556 | 16783 | 734.3
16 | `apache__incubator-seata::CVE-2025-32897` | 350 | 350 | 6793 | 315.4
17 | `apache__inlong::CVE-2025-27531` | 20 | 20 | 19871 | 885.3
18 | `apache__iotdb::CVE-2025-26795` | 165 | 165 | 24352 | 1106.5
19 | `apache__iotdb::CVE-2025-26864` | 165 | 165 | 24352 | 1069.5
20 | `apache__jackrabbit::CVE-2025-53689` | 6246 | 6246 | 14077 | 638.7
21 | `apache__myfaces::CVE-2011-4367` | 844 | 844 | 5979 | 262.1
22 | `apache__sling-org-apache-sling-servlets-resolver::CVE-2024-23673` | 37 | 37 | 290 | 16.1
23 | `apache__sling-org-apache-sling-xss::CVE-2016-5394` | 17 | 17 | 215 | 12.4
24 | `apache__tika::CVE-2018-11762` | 79 | 79 | 4611 | 214.3
25 | `apache__tomcat::CVE-2025-24813` | 794 | 794 | 16918 | 758.5
26 | `apache__tomcat::CVE-2025-48988` | 1869 | 1869 | 17221 | 756.8
27 | `apache__tomcat::CVE-2025-49125` | 823 | 823 | 17519 | 765.8
28 | `apache__tomcat::CVE-2025-52520` | 8313 | 8313 | 18254 | 824.8
29 | `apache__tomcat::CVE-2025-53506` | 2265 | 2265 | 17518 | 781.2
30 | `api-platform__core::CVE-2026-49858` | 79 | 79 | 2133 | 94.5
