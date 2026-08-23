# Recall Candidate List Judge Summary

This report summarizes advisory TraeX/LLM-as-judge list-wise scores over shuffled recall candidates.
It is separate from embedding recall metrics and should only guide whether a reranker/query A/B is worth running.

## Summary

- Judge prompt shards: 12
- Parsed prompt shards: 11
- Missing prompt shards: 0
- Invalid prompt shards: 2
- Candidate score parse issues: 0
- Identities: 6
- Identities with scored known-anchor candidates: 0
- Identity coverage gaps: 6
- Judge rerank hit counts: {'top_1': 0, 'top_3': 0, 'top_5': 0, 'top_10': 0}
- Judge rerank hit rates over eligible identities: {'top_1': None, 'top_3': None, 'top_5': None, 'top_10': None}

## Identity Rows

| Identity | Judge Anchor Rank | Original Anchor Rank | Judge Top Is Anchor | Judge Top Original Rank | Judge Top File |
| --- | ---: | ---: | --- | ---: | --- |
| `apache__axis-axis1-java::CVE-2023-51441` |  |  | False | 5 | axis-codegen/src/main/java/org/apache/axis/wsdl/toJava/JavaServiceImplWriter.java |
| `apolloconfig__apollo::CVE-2024-43397` |  |  | False | 11 | apollo-adminservice/src/main/java/com/ctrip/framework/apollo/adminservice/controller/ItemController.java |
| `jeecgboot__jeecgboot::CVE-2025-14908` |  |  | False | 4 | jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/shiro/ShiroRealm.java |
| `okta__okta-sdk-java::CVE-2025-66033` |  |  | False | 16 | api/src/main/java/com/okta/sdk/client/MultiThreadingWarningUtil.java |
| `steve-community__steve::CVE-2026-28230` |  |  | False | 17 | src/main/java/de/rwth/idsg/steve/repository/impl/SettingsRepositoryImpl.java |
| `swagger-api__swagger-codegen::CVE-2021-21363` |  |  | False | 6 | samples/client/petstore/java/jersey2/src/main/java/io/swagger/client/ApiClient.java |

## Policy

- Hidden known-anchor labels are used only after judge completion for offline diagnostic statistics.
- Do not convert judge choices into training labels, guideline text, regex fallback, or production routing without a separate reviewed experiment.
- A strong judge rerank hit rate motivates a same-identity reranker A/B; it is not itself a paper-facing recall result.
- If no judged candidate set contains known-anchor overlap, this report is a Top-N semantic-quality sample and cannot evaluate anchor reranking.
