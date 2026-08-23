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
      "candidate_id": "C001",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/controller/UserInfoController.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024 Apollo Authors\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  * http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  *\n16:  */\n17: package com.ctrip.framework.apollo.portal.controller;\n18: \n19: import com.ctrip.framework.apollo.common.exception.BadRequestException;\n20: import com.ctrip.framework.apollo.core.utils.StringUtils;\n21: import com.ctrip.framework.apollo.portal.entity.bo.UserInfo;\n22: import com.ctrip.framework.apollo.portal.entity.po.UserPO;\n23: import com.ctrip.framework.apollo.portal.spi.LogoutHandler;\n24: import com.ctrip.framework.apollo.portal.spi.UserInfoHolder;\n25: import com.ctrip.framework.apollo.portal.spi.UserService;\n26: import com.ctrip.framewo",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C002",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/service/ServerConfigService.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024 Apollo Authors\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  * http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  *\n16:  */\n17: package com.ctrip.framework.apollo.portal.service;\n18: \n19: \n20: import com.ctrip.framework.apollo.common.utils.BeanUtils;\n21: import com.ctrip.framework.apollo.portal.api.AdminServiceAPI;\n22: import com.ctrip.framework.apollo.portal.api.AdminServiceAPI.ServerConfigAPI;\n23: import com.ctrip.framework.apollo.portal.entity.po.ServerConfig;\n24: import com.ctrip.framework.apollo.portal.environment.Env;\n25: import com.ctrip.framework.apollo.portal.repository.ServerConfigRepository;\n26: import com.ctrip.framework.apollo.portal.spi.UserInfoHolde",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C003",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/openapi/server/service/ServerItemOpenApiService.java",
      "lines": {
        "end": 115,
        "start": 41
      },
      "snippet": "41:   }\n42: \n43:   @Override\n44:   public OpenItemDTO getItem(String appId, String env, String clusterName, String namespaceName,\n45:       String key) {\n46:     ItemDTO itemDTO = itemService.loadItem(Env.valueOf(env), appId, clusterName, namespaceName, key);\n47:     return itemDTO == null ? null : OpenApiBeanUtils.transformFromItemDTO(itemDTO);\n48:   }\n49: \n50:   @Override\n51:   public OpenItemDTO createItem(String appId, String env, String clusterName, String namespaceName,\n52:       OpenItemDTO itemDTO) {\n53: \n54:     ItemDTO toCreate = OpenApiBeanUtils.transformToItemDTO(itemDTO);\n55: \n56:     //protect\n57:     toCreate.setLineNum(0);\n58:     toCreate.setId(0);\n59:     toCreate.setDataChangeLastModifiedBy(toCreate.getDataChangeCreatedBy());\n60:     toCreate.setDataChangeLastModifiedTime(null);\n61:     toCreate.setDataChangeCreatedTime(null);\n62: \n63:     ItemDTO createdItem = itemService.createItem(appId, Env.valueOf(env),\n64:         clusterName, namespaceName, toCreate);\n65:     return OpenApiBeanUtils.transformFromItemDTO(createdItem);\n66:   }\n67: \n68:   @Override\n69:   public void updateItem(String appId, String env, String clusterName, String namespaceName,\n70:       OpenI",
      "span_kind": "sliding_window",
      "symbol": "ServerItemOpenApiService"
    },
    {
      "candidate_id": "C004",
      "file": "apollo-adminservice/src/main/java/com/ctrip/framework/apollo/adminservice/controller/ItemController.java",
      "lines": {
        "end": 200,
        "start": 121
      },
      "snippet": "121:                         @PathVariable(\"itemId\") long itemId,\n122:                         @RequestBody ItemDTO itemDTO) {\n123:     Item managedEntity = itemService.findOne(itemId);\n124:     if (managedEntity == null) {\n125:       throw NotFoundException.itemNotFound(appId, clusterName, namespaceName, itemId);\n126:     }\n127: \n128:     Namespace namespace = namespaceService.findOne(appId, clusterName, namespaceName);\n129:     // In case someone constructs an attack scenario\n130:     if (namespace == null || namespace.getId() != managedEntity.getNamespaceId()) {\n131:       throw BadRequestException.namespaceNotMatch();\n132:     }\n133: \n134:     Item entity = BeanUtils.transform(Item.class, itemDTO);\n135: \n136:     ConfigChangeContentBuilder builder = new ConfigChangeContentBuilder();\n137: \n138:     Item beforeUpdateItem = BeanUtils.transform(Item.class, managedEntity);\n139: \n140:     //protect. only value,type,comment,lastModifiedBy can be modified\n141:     managedEntity.setType(entity.getType());\n142:     managedEntity.setValue(entity.getValue());\n143:     managedEntity.setComment(entity.getComment());\n144:     managedEntity.setDataChangeLastModifiedBy(entity.getDataChangeLastM",
      "span_kind": "sliding_window",
      "symbol": "update"
    },
    {
      "candidate_id": "C005",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/controller/AppController.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import com.ctrip.framework.apollo.portal.spi.UserInfoHolder;\n42: import com.ctrip.framework.apollo.portal.util.RoleUtils;\n43: import com.google.common.base.Strings;\n44: import com.google.common.collect.Sets;\n45: import org.springframework.context.ApplicationEventPublisher;\n46: import org.springframework.data.domain.Pageable;\n47: import org.springframework.http.HttpStatus;\n48: import org.springframework.http.ResponseEntity;\n49: import org.springframework.security.access.prepost.PreAuthorize;\n50: import org.springframework.web.bind.annotation.DeleteMapping;\n51: import org.springframework.web.bind.annotation.GetMapping;\n52: import org.springframework.web.bind.annotation.PathVariable;\n53: import org.springframework.web.bind.annotation.PostMapping;\n54: import org.springframework.web.bind.annotation.PutMapping;\n55: import org.springframework.web.bind.annotation.RequestBody;\n56: import org.springframework.web.bind.annotation.RequestMapping;\n57: import org.springframework.web.bind.annotation.RequestParam;\n58: import org.springframework.web.bind.annotation.RestController;\n59: import org.springframework.web.client.HttpClientErrorException;\n60: \n61: import javax.validation.Valid;\n62: impo",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C006",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/openapi/v1/controller/ItemController.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import org.springframework.web.bind.annotation.RequestParam;\n42: import org.springframework.web.bind.annotation.RestController;\n43: \n44: import javax.servlet.http.HttpServletRequest;\n45: import javax.validation.Valid;\n46: import javax.validation.constraints.Positive;\n47: import javax.validation.constraints.PositiveOrZero;\n48: \n49: @Validated\n50: @RestController(\"openapiItemController\")\n51: @RequestMapping(\"/openapi/v1/envs/{env}\")\n52: public class ItemController {\n53: \n54:   private final ItemService itemService;\n55:   private final UserService userService;\n56:   private final ItemOpenApiService itemOpenApiService;\n57: \n58:   private static final int ITEM_COMMENT_MAX_LENGTH = 256;\n59: \n60:   public ItemController(final ItemService itemService, final UserService userService,\n61:       ItemOpenApiService itemOpenApiService) {\n62:     this.itemService = itemService;\n63:     this.userService = userService;\n64:     this.itemOpenApiService = itemOpenApiService;\n65:   }\n66: \n67:   @GetMapping(value = \"/apps/{appId}/clusters/{clusterName}/namespaces/{namespaceName}/items/{key:.+}\")\n68:   public OpenItemDTO getItem(@PathVariable String appId, @PathVariable String env, @PathVariable Stri",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C007",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/controller/UserInfoController.java",
      "lines": {
        "end": 119,
        "start": 41
      },
      "snippet": "41: \n42: @RestController\n43: public class UserInfoController {\n44: \n45:   private final UserInfoHolder userInfoHolder;\n46:   private final LogoutHandler logoutHandler;\n47:   private final UserService userService;\n48:   private final AuthUserPasswordChecker passwordChecker;\n49: \n50:   public UserInfoController(\n51:       final UserInfoHolder userInfoHolder,\n52:       final LogoutHandler logoutHandler,\n53:       final UserService userService,\n54:       final AuthUserPasswordChecker passwordChecker) {\n55:     this.userInfoHolder = userInfoHolder;\n56:     this.logoutHandler = logoutHandler;\n57:     this.userService = userService;\n58:     this.passwordChecker = passwordChecker;\n59:   }\n60: \n61:   @PreAuthorize(value = \"@permissionValidator.isSuperAdmin()\")\n62:   @PostMapping(\"/users\")\n63:   public void createOrUpdateUser(\n64:       @RequestParam(value = \"isCreate\", defaultValue = \"false\") boolean isCreate,\n65:       @RequestBody UserPO user) {\n66:     if (StringUtils.isContainEmpty(user.getUsername(), user.getPassword())) {\n67:       throw new BadRequestException(\"Username and password can not be empty.\");\n68:     }\n69: \n70:     CheckResult pwdCheckRes = passwordChecker.checkWeakPasswor",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C008",
      "file": "apollo-portal/src/main/resources/application-oidc-sample.yml",
      "lines": {
        "end": 63,
        "start": 1
      },
      "snippet": "1: #\n2: # Copyright 2024 Apollo Authors\n3: #\n4: # Licensed under the Apache License, Version 2.0 (the \"License\");\n5: # you may not use this file except in compliance with the License.\n6: # You may obtain a copy of the License at\n7: #\n8: # http://www.apache.org/licenses/LICENSE-2.0\n9: #\n10: # Unless required by applicable law or agreed to in writing, software\n11: # distributed under the License is distributed on an \"AS IS\" BASIS,\n12: # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13: # See the License for the specific language governing permissions and\n14: # limitations under the License.\n15: #\n16: server:\n17:   # 解析反向代理请求头\n18:   forward-headers-strategy: framework\n19: spring:\n20:   security:\n21:     oauth2:\n22:       client:\n23:         provider:\n24:           # provider-name 是 oidc 提供者的名称, 任意字符均可, registration 的配置需要用到这个名称\n25:           <fill-in-the-provider-name-here>:\n26:             # 必须是 https, oidc 的 issuer-uri, 和 jwt 的 issuer-uri 一致的话直接引用即可, 也可以单独设置\n27:             issuer-uri: ${spring.security.oauth2.resourceserver.jwt.issuer-uri}\n28:         registration:\n29:           # registration-name 是 oidc 客户端的名称, 任意字符均可, oidc 登录必须配置一个 authorization_code 类型",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C009",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/controller/AppController.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81:       final UserInfoHolder userInfoHolder,\n82:       final AppService appService,\n83:       final PortalSettings portalSettings,\n84:       final ApplicationEventPublisher publisher,\n85:       final RolePermissionService rolePermissionService,\n86:       final RoleInitializationService roleInitializationService,\n87:       final AdditionalUserInfoEnrichService additionalUserInfoEnrichService) {\n88:     this.userInfoHolder = userInfoHolder;\n89:     this.appService = appService;\n90:     this.portalSettings = portalSettings;\n91:     this.publisher = publisher;\n92:     this.rolePermissionService = rolePermissionService;\n93:     this.roleInitializationService = roleInitializationService;\n94:     this.additionalUserInfoEnrichService = additionalUserInfoEnrichService;\n95:   }\n96: \n97:   @GetMapping\n98:   public List<App> findApps(@RequestParam(value = \"appIds\", required = false) String appIds) {\n99:     if (Strings.isNullOrEmpty(appIds)) {\n100:       return appService.findAll();\n101:     }\n102:     return appService.findByAppIds(Sets.newHashSet(appIds.split(\",\")));\n103:   }\n104: \n105:   @GetMapping(\"/by-owner\")\n106:   public List<App> findAppsByOwner(@RequestParam(\"owner\") String owner, ",
      "span_kind": "sliding_window",
      "symbol": "AppController"
    },
    {
      "candidate_id": "C010",
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/spi/oidc/OidcAuthenticationSuccessEventListener.java",
      "lines": {
        "end": 142,
        "start": 81
      },
      "snippet": "81:     UserInfo newUserInfo = new UserInfo();\n82:     newUserInfo.setUserId(subject);\n83:     newUserInfo.setName(userDisplayName);\n84:     newUserInfo.setEmail(email);\n85:     if (this.contains(subject)) {\n86:       this.oidcLocalUserService.updateUserInfo(newUserInfo);\n87:       return;\n88:     }\n89:     this.oidcLocalUserService.createLocalUser(newUserInfo);\n90:   }\n91: \n92:   private void logOidc(OidcUser oidcUser, String subject, String userDisplayName,\n93:       String email) {\n94:     oidcLog.debug(\"oidc authentication success, sub=[{}] userDisplayName=[{}] email=[{}]\", subject,\n95:         userDisplayName, email);\n96:     if (oidcLog.isTraceEnabled()) {\n97:       Map<String, Object> claims = oidcUser.getClaims();\n98:       for (Entry<String, Object> entry : claims.entrySet()) {\n99:         oidcLog.trace(\"oidc authentication claims [{}={}]\", entry.getKey(), entry.getValue());\n100:       }\n101:     }\n102:   }\n103: \n104:   private boolean contains(String userId) {\n105:     if (this.userIdCache.containsKey(userId)) {\n106:       return true;\n107:     }\n108:     UserInfo userInfo = this.oidcLocalUserService.findByUserId(userId);\n109:     if (userInfo != null) {\n110:       this.u",
      "span_kind": "sliding_window",
      "symbol": "oidcUserLogin"
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-controlled resource identifiers, namespace IDs, tenant IDs, object IDs, or bulk-operation targets carried in a request body into bulk updates, synchronization operations, mutations, or administrative effects that act on those body-selected resources. Report code paths where the body-selected resources are not validated to match the URL path parameters or the resource identity used by the authorization check. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should validate every body-selected target against the path-scoped resource identity before the permission check and before the mutation.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 1
  }
}

Return JSON only. Do not call tools or run commands.