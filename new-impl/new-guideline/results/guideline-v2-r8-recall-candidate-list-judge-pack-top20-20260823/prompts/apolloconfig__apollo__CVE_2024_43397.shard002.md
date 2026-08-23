# Recall Candidate List Judge

This is an advisory semantic QA task for recall reranking diagnostics.
It does not change retrieval rankings and it is not a vulnerability verdict.

Instructions:
{
  "expected_json": {
    "candidate_scores": [
      {
        "audit_priority": "high|medium|low|none",
        "candidate_id": "C001",
        "key_evidence": [
          "evidence in this snippet"
        ],
        "rationale": "short explanation",
        "relevance": 0.0
      }
    ],
    "confidence": 0.0,
    "missing_information": [
      "what would be needed to judge better"
    ],
    "top_choices": [
      "C001"
    ]
  },
  "review_scope": [
    "Judge semantic match to the guideline only.",
    "For each candidate, estimate whether it is useful as an audit entry point.",
    "Use only the guideline text, file path, symbol, and source snippet shown here.",
    "Do not infer from CVE IDs, known-anchor labels, original rank, original score, or benchmark metadata; those fields are intentionally omitted.",
    "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only."
  ],
  "task": "Score anonymous recall candidates for one security guideline."
}

Payload:
{
  "candidates": [
    {
      "candidate_id": "C011",
      "file": "apollo-common/src/main/java/com/ctrip/framework/apollo/common/controller/WebMvcConfig.java",
      "lines": {
        "end": 72,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024 Apollo Authors\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  * http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  *\n16:  */\n17: package com.ctrip.framework.apollo.common.controller;\n18: \n19: import java.util.List;\n20: import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;\n21: import org.springframework.boot.web.server.MimeMappings;\n22: import org.springframework.boot.web.server.WebServerFactoryCustomizer;\n23: import org.springframework.context.annotation.Configuration;\n24: import org.springframework.data.domain.PageRequest;\n25: import org.springframework.data.web.PageableHandlerMethodArgumentResolver;\n26: import org.springframework.web.",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C012",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/spi/oidc/OidcAuthenticationSuccessEventListener.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41:   private static final Logger oidcLog = LoggerFactory.getLogger(\n42:       OidcAuthenticationSuccessEventListener.class.getName() + \".oidc\");\n43: \n44:   private static final Logger jwtLog = LoggerFactory.getLogger(\n45:       OidcAuthenticationSuccessEventListener.class.getName() + \".jwt\");\n46: \n47:   private final OidcLocalUserService oidcLocalUserService;\n48: \n49:   private final OidcExtendProperties oidcExtendProperties;\n50: \n51:   private final ConcurrentMap<String, String> userIdCache = new ConcurrentHashMap<>();\n52: \n53:   public OidcAuthenticationSuccessEventListener(\n54:       OidcLocalUserService oidcLocalUserService, OidcExtendProperties oidcExtendProperties) {\n55:     this.oidcLocalUserService = oidcLocalUserService;\n56:     this.oidcExtendProperties = oidcExtendProperties;\n57:   }\n58: \n59:   @Override\n60:   public void onApplicationEvent(AuthenticationSuccessEvent event) {\n61:     Object principal = event.getAuthentication().getPrincipal();\n62:     if (principal instanceof OidcUser) {\n63:       this.oidcUserLogin((OidcUser) principal);\n64:       return;\n65:     }\n66:     if (principal instanceof Jwt) {\n67:       this.jwtLogin((Jwt) principal);\n68:       return;\n69:  ",
      "span_kind": "sliding_window",
      "symbol": "OidcAuthenticationSuccessEventListener"
    },
    {
      "candidate_id": "C013",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/service/AppService.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81:     this.appAPI = appAPI;\n82:     this.appRepository = appRepository;\n83:     this.clusterService = clusterService;\n84:     this.appNamespaceService = appNamespaceService;\n85:     this.roleInitializationService = roleInitializationService;\n86:     this.rolePermissionService = rolePermissionService;\n87:     this.favoriteService = favoriteService;\n88:     this.userService = userService;\n89:     this.apolloAuditLogApi = apolloAuditLogApi;\n90:     this.publisher = publisher;\n91:   }\n92: \n93: \n94:   public List<App> findAll() {\n95:     Iterable<App> apps = appRepository.findAll();\n96: \n97:     return Lists.newArrayList(apps);\n98:   }\n99: \n100:   public PageDTO<App> findAll(Pageable pageable) {\n101:     Page<App> apps = appRepository.findAll(pageable);\n102: \n103:     return new PageDTO<>(apps.getContent(), pageable, apps.getTotalElements());\n104:   }\n105: \n106:   public PageDTO<App> searchByAppIdOrAppName(String query, Pageable pageable) {\n107:     Page<App> apps = appRepository.findByAppIdContainingOrNameContaining(query, query, pageable);\n108: \n109:     return new PageDTO<>(apps.getContent(), pageable, apps.getTotalElements());\n110:   }\n111: \n112:   public List<App> findByAppIds(Se",
      "span_kind": "sliding_window",
      "symbol": "AppService"
    },
    {
      "candidate_id": "C014",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/spi/oidc/OidcLocalUserServiceImpl.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024 Apollo Authors\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  * http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  *\n16:  */\n17: package com.ctrip.framework.apollo.portal.spi.oidc;\n18: \n19: import com.ctrip.framework.apollo.core.utils.StringUtils;\n20: import com.ctrip.framework.apollo.portal.entity.bo.UserInfo;\n21: import com.ctrip.framework.apollo.portal.entity.po.UserPO;\n22: import com.ctrip.framework.apollo.portal.repository.UserRepository;\n23: import java.util.ArrayList;\n24: import java.util.Collection;\n25: import java.util.Collections;\n26: import java.util.HashMap;\n27: import java.util.List;\n28: import java.util.Map;\n29: import java.util.stream.Collectors;\n30:",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C015",
      "file": "apollo-portal/src/main/resources/application.yml",
      "lines": {
        "end": 49,
        "start": 1
      },
      "snippet": "1: #\n2: # Copyright 2024 Apollo Authors\n3: #\n4: # Licensed under the Apache License, Version 2.0 (the \"License\");\n5: # you may not use this file except in compliance with the License.\n6: # You may obtain a copy of the License at\n7: #\n8: # http://www.apache.org/licenses/LICENSE-2.0\n9: #\n10: # Unless required by applicable law or agreed to in writing, software\n11: # distributed under the License is distributed on an \"AS IS\" BASIS,\n12: # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13: # See the License for the specific language governing permissions and\n14: # limitations under the License.\n15: #\n16: spring:\n17:   profiles:\n18:     active: ${apollo_profile}\n19:   jpa:\n20:     properties:\n21:       hibernate:\n22:         metadata_builder_contributor: com.ctrip.framework.apollo.common.jpa.SqlFunctionsMetadataBuilderContributor\n23:         query:\n24:           plan_cache_max_size: 192 # limit query plan cache max size\n25:   session:\n26:     store-type: jdbc\n27:     jdbc:\n28:       initialize-schema: never\n29:   servlet:\n30:     multipart:\n31:       max-file-size: 200MB  # import data configs\n32:       max-request-size: 200MB\n33: server:\n34:   compression:\n35: ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C016",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/spi/configuration/AuthConfiguration.java",
      "lines": {
        "end": 440,
        "start": 361
      },
      "snippet": "361:             PasswordEncoder passwordEncoder,\n362:             AuthenticationManagerBuilder auth,\n363:             DataSource datasource,\n364:             EntityManagerFactory entityManagerFactory) throws Exception {\n365:       return SpringSecurityAuthAutoConfiguration\n366:           .jdbcUserDetailsManager(passwordEncoder, auth, datasource, entityManagerFactory);\n367:     }\n368: \n369:     @Bean\n370:     @ConditionalOnMissingBean(UserService.class)\n371:     public OidcLocalUserService oidcLocalUserService(JdbcUserDetailsManager userDetailsManager,\n372:         UserRepository userRepository) {\n373:       return new OidcLocalUserServiceImpl(userDetailsManager, userRepository);\n374:     }\n375: \n376:     @Bean\n377:     public OidcAuthenticationSuccessEventListener oidcAuthenticationSuccessEventListener(\n378:         OidcLocalUserService oidcLocalUserService, OidcExtendProperties oidcExtendProperties) {\n379:       return new OidcAuthenticationSuccessEventListener(oidcLocalUserService, oidcExtendProperties);\n380:     }\n381:   }\n382: \n383:   @Profile(\"oidc\")\n384:   @EnableWebSecurity\n385:   @EnableGlobalMethodSecurity(prePostEnabled = true)\n386:   @Configuration\n387:   static class O",
      "span_kind": "sliding_window",
      "symbol": "jdbcUserDetailsManager"
    },
    {
      "candidate_id": "C017",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/controller/AppController.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024 Apollo Authors\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  * http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  *\n16:  */\n17: package com.ctrip.framework.apollo.portal.controller;\n18: \n19: \n20: import com.ctrip.framework.apollo.audit.annotation.ApolloAuditLog;\n21: import com.ctrip.framework.apollo.audit.annotation.OpType;\n22: import com.ctrip.framework.apollo.common.dto.AppDTO;\n23: import com.ctrip.framework.apollo.common.entity.App;\n24: import com.ctrip.framework.apollo.common.exception.BadRequestException;\n25: import com.ctrip.framework.apollo.common.http.MultiResponseEntity;\n26: import com.ctrip.framework.apollo.common.http.RichResponseEntity;\n27: import com.",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C018",
      "file": "apollo-configservice/src/main/java/com/ctrip/framework/apollo/configservice/util/AccessKeyUtil.java",
      "lines": {
        "end": 74,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024 Apollo Authors\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  * http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  *\n16:  */\n17: package com.ctrip.framework.apollo.configservice.util;\n18: \n19: import com.ctrip.framework.apollo.configservice.service.AccessKeyServiceWithCache;\n20: import com.ctrip.framework.apollo.core.signature.Signature;\n21: import com.google.common.base.Strings;\n22: import java.util.List;\n23: import javax.servlet.http.HttpServletRequest;\n24: import org.apache.commons.lang.StringUtils;\n25: import org.springframework.stereotype.Component;\n26: \n27: /**\n28:  * @author nisiyong\n29:  */\n30: @Component\n31: public class AccessKeyUtil {\n32: \n33:   private ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C019",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/spi/configuration/AuthConfiguration.java",
      "lines": {
        "end": 469,
        "start": 401
      },
      "snippet": "401:     protected void configure(HttpSecurity http) throws Exception {\n402:       http.csrf().disable();\n403:       http.authorizeRequests(requests -> requests.antMatchers(BY_PASS_URLS).permitAll());\n404:       http.authorizeRequests(requests -> requests.anyRequest().authenticated());\n405:       http.oauth2Login(configure ->\n406:           configure.clientRegistrationRepository(\n407:               new ExcludeClientCredentialsClientRegistrationRepository(\n408:                   this.clientRegistrationRepository)));\n409:       http.oauth2Client();\n410:       http.logout(configure -> {\n411:         configure.logoutUrl(\"/user/logout\");\n412:         OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(\n413:             this.clientRegistrationRepository);\n414:         logoutSuccessHandler.setPostLogoutRedirectUri(\"{baseUrl}\");\n415:         configure.logoutSuccessHandler(logoutSuccessHandler);\n416:       });\n417:       // make jwt optional\n418:       String jwtIssuerUri = this.oauth2ResourceServerProperties.getJwt().getIssuerUri();\n419:       if (!StringUtils.isBlank(jwtIssuerUri)) {\n420:         http.oauth2ResourceServer().jwt();\n421",
      "span_kind": "sliding_window",
      "symbol": "configure"
    },
    {
      "candidate_id": "C020",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/api/AdminServiceAPI.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024 Apollo Authors\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  * http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  *\n16:  */\n17: package com.ctrip.framework.apollo.portal.api;\n18: \n19: import com.ctrip.framework.apollo.audit.annotation.ApolloAuditLog;\n20: import com.ctrip.framework.apollo.audit.annotation.OpType;\n21: import com.ctrip.framework.apollo.common.dto.*;\n22: import com.ctrip.framework.apollo.openapi.dto.OpenItemDTO;\n23: import com.ctrip.framework.apollo.portal.entity.po.ServerConfig;\n24: import com.ctrip.framework.apollo.portal.environment.Env;\n25: import com.google.common.base.Joiner;\n26: import java.nio.charset.StandardCharsets;\n27: import java.util.Bas",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-controlled resource identifiers, namespace IDs, tenant IDs, object IDs, or bulk-operation targets carried in a request body into bulk updates, synchronization operations, mutations, or administrative effects that act on those body-selected resources. Report code paths where the body-selected resources are not validated to match the URL path parameters or the resource identity used by the authorization check. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should validate every body-selected target against the path-scoped resource identity before the permission check and before the mutation.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 2
  }
}

Return JSON only. Do not call tools or run commands.