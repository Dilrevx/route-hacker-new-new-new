# Recall Candidate Pair Judge Summary

This report summarizes advisory TraeX/LLM-as-judge choices over anonymous recall candidate pairs.
It is separate from embedding recall metrics and should only guide whether a reranker/query A/B is worth running.

## Summary

- Judge inputs: 6
- Parsed outputs: 6
- Missing outputs: 0
- Invalid outputs: 0
- Choice counts: {'A': 3, 'B': 2, 'neither': 1}
- Choice outcomes: {'anchor_overlap_chosen': 5, 'neither': 1}
- Anchor-overlap choice rate: 0.8333333333333334
- Top1 choice rate: 0.0
- Average scores: {'candidate_a_relevance': 0.26666666666666666, 'candidate_b_relevance': 0.3083333333333333, 'confidence': 0.8666666666666667}

## Rows

| Identity | Outcome | Choice | Anchor Rank | Top1 File | Anchor File | Rationale |
| --- | --- | --- | ---: | --- | --- | --- |
| `apache__axis-axis1-java::CVE-2023-51441` | `anchor_overlap_chosen` | `A` | 194 | axis-rt-jws/src/main/java/org/apache/axis/handlers/JWSHandler.java | axis-rt-core/src/main/java/org/apache/axis/client/ServiceFactory.java | Candidate A is a JNDI ObjectFactory implementation that obtains services via JNDI, directly matching the guideline's concern with naming-context and remote lookup APIs. The snippet shows the right imports and class structure but is cut off before the actual lookup sink. Candidate B is a JWS handler dealing with local file compilation and class loading, with no JNDI, LDAP, or RMI imports — it is unrelated to the guideline. |
| `apolloconfig__apollo::CVE-2024-43397` | `anchor_overlap_chosen` | `A` | 252 | apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/api/AdminServiceAPI.java | apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/controller/ItemController.java | Candidate A directly exhibits the guideline's core pattern: REST endpoints that accept body-selected resource targets (syncToNamespaces) and perform authorization checks on them, with a visible mismatch in diff() where the URL path {namespaceName} is not used in the auth check. Candidate B is a service-client API wrapper with only simple CRUD delegation and no body-vs-path validation logic in the shown snippet. |
| `jeecgboot__jeecgboot::CVE-2025-14908` | `anchor_overlap_chosen` | `B` | 275 | jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/common/system/util/JwtUtil.java | jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysTenantController.java | Candidate A is JWT authentication infrastructure (token creation/verification, error response formatting) — it does not trace resource identifiers into sensitive operations, so it is a poor match for the authorization_bypass guideline. Candidate B is a tenant controller with methods that accept tenant IDs and user IDs as parameters and perform administrative mutations (exit tenant, change owner, invite user, manage tenant packs). The exitUserTenant method demonstrates the guideline's core pattern: check user-tenant relationship, verify credentials, then perform the effect. Several methods (notably changeOwenUserTenant) accept attacker-controllable resource identifiers without visible authorization guards in the snippet, making them directly useful for a downstream security audit. |
| `okta__okta-sdk-java::CVE-2025-66033` | `anchor_overlap_chosen` | `A` | 215 | pom.xml | api/src/main/java/com/okta/sdk/helper/PaginationUtil.java | Candidate A contains method-level code that manipulates objects (URL, HTTP headers, query strings) and could in principle be part of a check-then-use chain, but the snippet itself shows only parsing utilities — no check of mutable state followed by a sensitive effect. Candidate B is a POM dependency listing, which is entirely irrelevant to any security guideline about concurrent object lifecycle. A is the marginally better choice, but neither is useful for a downstream security audit of this guideline. |
| `swagger-api__swagger-codegen::CVE-2021-21363` | `anchor_overlap_chosen` | `B` | 136 | modules/swagger-codegen/src/main/java/io/swagger/codegen/AbstractGenerator.java | modules/swagger-generator/src/main/java/io/swagger/generator/online/Generator.java | Candidate A contains only conventional file I/O (writeToFile, readTemplate, getTemplateReader) with no temporary file creation or TOCTOU patterns. Candidate B contains the exact guideline-described anti-pattern: getTmpFolder() creates a temp file via createTempFile, immediately deletes it, then creates a directory at the same path via mkdir, leaving a race window where another actor could hijack the path between deletion and directory creation. This is a direct instance of the TOCTOU check-use race pattern the guideline targets. |
| `steve-community__steve::CVE-2026-28230` | `neither` | `neither` | 218 | src/main/java/de/rwth/idsg/steve/config/ApiAuthenticationManager.java | src/main/java/de/rwth/idsg/steve/service/CentralSystemService16_Service.java | Neither candidate shows the SQL injection pattern described in the guideline. Candidate A is an authentication manager using PasswordEncoder and Spring Security — no SQL construction is visible. Candidate B is an OCPP service layer passing parameters to repository methods — no SQL, JDBC, or query builder fragments are visible. The guideline requires concrete evidence of untrusted values concatenated into SQL syntax without parameter binding; both snippets delegate data access to hidden layers, making neither a useful match for a downstream security audit targeting this mechanism. |

## Policy

- Hidden expected labels are used only after judge completion for offline diagnostic statistics.
- Do not convert judge choices into training labels, guideline text, regex fallback, or production routing without a separate reviewed experiment.
- A strong anchor-overlap choice rate motivates a same-identity reranker A/B; it is not itself a paper-facing recall result.
