# Recall Candidate Pair Judge

This is an advisory semantic QA task for recall diagnostics.
It does not change retrieval rankings and it is not a vulnerability verdict.

Instructions:
{
  "expected_json": {
    "candidate_a_relevance": 0.0,
    "candidate_b_relevance": 0.0,
    "choice": "A|B|tie|neither",
    "confidence": 0.0,
    "key_evidence": [
      "evidence in the chosen snippet"
    ],
    "missing_information": [
      "what would be needed to judge better"
    ],
    "rationale": "short explanation"
  },
  "review_scope": [
    "Judge semantic match to the guideline only.",
    "Choose the candidate that is more useful for a downstream security audit.",
    "Use only the guideline text, file path, symbol, and source snippet shown here.",
    "Do not infer from CVE IDs, known-anchor labels, rank, score, or benchmark metadata; those fields are intentionally omitted.",
    "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only."
  ],
  "task": "Compare two anonymous recall candidates for one security guideline."
}

Payload:
{
  "candidates": [
    {
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/controller/ItemController.java",
      "label": "A",
      "lines": {
        "end": 240,
        "start": 161
      },
      "snippet": "161:     return items;\n162:   }\n163: \n164:   @GetMapping(\"/apps/{appId}/envs/{env}/clusters/{clusterName}/namespaces/{namespaceName}/branches/{branchName}/items\")\n165:   public List<ItemDTO> findBranchItems(@PathVariable(\"appId\") String appId, @PathVariable String env,\n166:                                        @PathVariable(\"clusterName\") String clusterName,\n167:                                        @PathVariable(\"namespaceName\") String namespaceName,\n168:                                        @PathVariable(\"branchName\") String branchName) {\n169: \n170:     return findItems(appId, env, branchName, namespaceName, \"lastModifiedTime\");\n171:   }\n172: \n173:   @PostMapping(value = \"/namespaces/{namespaceName}/diff\", consumes = {\"application/json\"})\n174:   public List<ItemDiffs> diff(@RequestBody NamespaceSyncModel model) {\n175:     checkModel(!model.isInvalid());\n176: \n177:     List<ItemDiffs> itemDiffs = configService.compare(model.getSyncToNamespaces(), model.getSyncItems());\n178: \n179:     for (ItemDiffs diff : itemDiffs) {\n180:       NamespaceIdentifier namespace = diff.getNamespace();\n181:       if (namespace == null) {\n182:         continue;\n183:       }\n184: \n185:       if (permissionValidator\n186:           .shouldHideConfigToCurrentUser(namespace.getAppId(), namespace.getEnv().getName(), namespace.getNamespaceName())) {\n187:         diff.setDiffs(new ItemChangeSets());\n188:         diff.setExtInfo(\"You are not this project's administrator, nor you have edit or release permission for the namespace in environment: \" + namespace.getEnv());\n189:       }\n190:     }\n191: \n192:     return itemDiffs;\n193:   }\n194: \n195:   @PutMapping(value = \"/apps/{appId}/namespaces/{namespaceName}/items\", consumes = {\"application/json\"})\n196:   public ResponseEntity<Void> update(@PathVariable String appId, @PathVariable String namespaceName,\n197:                                      @RequestBody NamespaceSyncModel model) {\n198:     checkModel(!model.isInvalid());\n199:     boolean hasPermission = permissionValidator.hasModifyNamespacePermission(appId, namespaceName);\n200:     Env envNoPermission = null;\n201:     // if uses has ModifyNamespace permission then he has permission\n202:     if (!hasPermission) {\n203:       // else check if user has every env's ModifyNamespace permission\n204:       hasPermission = true;\n205:       for (NamespaceIdentifier namespaceIdentifier : model.getSyncToNamespaces()) {\n206:         // once user has not one of the env's ModifyNamespace permission, then break the loop\n207:         hasPermission &= permissionValidator.hasModifyNamespacePermission(namespaceIdentifier.getAppId(), namespaceIdentifier.getNamespaceName(), namespaceIdentifier.getEnv().toString());\n208:         if (!hasPermission) {\n209:           envNoPermission = namespaceIdentifier.getEnv();\n210:           break;\n211:         }\n212:       }\n213:     }\n214:     if (hasPermission) {\n215:       configService.syncItems(model.getSyncToNamespaces(), model.getSyncItems());\n216:       return ResponseEntity.status(HttpStatus.OK).build();\n217:     }\n218:     throw new AccessDeniedException(String.format(\"You don't have the permission to modify environment: %s\", envNoPermission));\n219:   }\n220: \n221:   @PreAuthorize(value = \"@permissionValidator.hasModifyNamespacePermission(#appId, #namespaceName, #env)\")\n222:   @PostMapping(value = \"/apps/{appId}/envs/{env}/clusters/{clusterName}/namespaces/{namespaceName}/syntax-check\", consumes = {\n223:       \"application/json\"})\n224:   public ResponseEntity<Void> syntaxCheckText(@PathVariable String appId, @PathVariable String env,\n225:       @PathVariable String clusterName, @PathVariable String namespaceName, @RequestBody NamespaceTextModel model) {\n226: \n227:     doSyntaxCheck(model);\n228: \n229:     return ResponseEntity.ok().build();\n230:   }\n231: \n232:   @PreAuthorize(value = \"@permissionValidator.hasModifyNamespacePermission(#appId, #namespaceName, #env)\")\n233:   @PutMapping(\"/apps/{appId}/envs/{env}/clusters/{clusterNa",
      "span_kind": "sliding_window",
      "symbol": "findItems"
    },
    {
      "file": "apollo-portal/src/main/java/com/ctrip/framework/apollo/portal/api/AdminServiceAPI.java",
      "label": "B",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024 Apollo Authors\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  * http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  *\n16:  */\n17: package com.ctrip.framework.apollo.portal.api;\n18: \n19: import com.ctrip.framework.apollo.audit.annotation.ApolloAuditLog;\n20: import com.ctrip.framework.apollo.audit.annotation.OpType;\n21: import com.ctrip.framework.apollo.common.dto.*;\n22: import com.ctrip.framework.apollo.openapi.dto.OpenItemDTO;\n23: import com.ctrip.framework.apollo.portal.entity.po.ServerConfig;\n24: import com.ctrip.framework.apollo.portal.environment.Env;\n25: import com.google.common.base.Joiner;\n26: import java.nio.charset.StandardCharsets;\n27: import java.util.Base64;\n28: import org.springframework.boot.actuate.health.Health;\n29: import org.springframework.core.ParameterizedTypeReference;\n30: import org.springframework.http.HttpEntity;\n31: import org.springframework.http.HttpHeaders;\n32: import org.springframework.http.MediaType;\n33: import org.springframework.http.ResponseEntity;\n34: import org.springframework.stereotype.Service;\n35: import org.springframework.util.CollectionUtils;\n36: import org.springframework.util.LinkedMultiValueMap;\n37: import org.springframework.util.MultiValueMap;\n38: import java.util.Arrays;\n39: import java.util.Collections;\n40: import java.util.List;\n41: import java.util.Map;\n42: import java.util.Set;\n43: \n44: \n45: @Service\n46: public class AdminServiceAPI {\n47: \n48:   @Service\n49:   public static class HealthAPI extends API {\n50: \n51:     public Health health(Env env) {\n52:       return restTemplate.get(env, \"/health\", Health.class);\n53:     }\n54:   }\n55: \n56:   @Service\n57:   public static class AppAPI extends API {\n58: \n59:     public AppDTO loadApp(Env env, String appId) {\n60:       return restTemplate.get(env, \"apps/{appId}\", AppDTO.class, appId);\n61:     }\n62: \n63:     @ApolloAuditLog(type = OpType.RPC, name = \"App.createInRemote\")\n64:     public AppDTO createApp(Env env, AppDTO app) {\n65:       return restTemplate.post(env, \"apps\", app, AppDTO.class);\n66:     }\n67: \n68:     @ApolloAuditLog(type = OpType.RPC, name = \"App.updateInRemote\")\n69:     public void updateApp(Env env, AppDTO app) {\n70:       restTemplate.put(env, \"apps/{appId}\", app, app.getAppId());\n71:     }\n72: \n73:     @ApolloAuditLog(type = OpType.RPC, name = \"App.deleteInRemote\")\n74:     public void deleteApp(Env env, String appId, String operator) {\n75:       restTemplate.delete(env, \"/apps/{appId}?operator={operator}\", appId, operator);\n76:     }\n77:   }\n78: \n79: \n80:   @Service",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-controlled resource identifiers, namespace IDs, tenant IDs, object IDs, or bulk-operation targets carried in a request body into bulk updates, synchronization operations, mutations, or administrative effects that act on those body-selected resources. Report code paths where the body-selected resources are not validated to match the URL path parameters or the resource identity used by the authorization check. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should validate every body-selected target against the path-scoped resource identity before the permission check and before the mutation.",
  "judge_mode": "recall_candidate_pair_advisory"
}

Return JSON only. Do not call tools or run commands.