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
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/common/system/util/JwtUtil.java",
      "label": "A",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package org.jeecg.common.system.util;\n2: \n3: import com.auth0.jwt.JWT;\n4: import com.auth0.jwt.JWTVerifier;\n5: import com.auth0.jwt.algorithms.Algorithm;\n6: import com.auth0.jwt.exceptions.JWTDecodeException;\n7: import com.auth0.jwt.interfaces.DecodedJWT;\n8: import com.fasterxml.jackson.databind.ObjectMapper;\n9: import com.google.common.base.Joiner;\n10: \n11: import java.io.IOException;\n12: import java.io.OutputStream;\n13: import java.util.Date;\n14: import java.util.Objects;\n15: import java.util.stream.Collectors;\n16: \n17: import jakarta.servlet.ServletResponse;\n18: import jakarta.servlet.http.HttpServletRequest;\n19: import jakarta.servlet.http.HttpServletResponse;\n20: import jakarta.servlet.http.HttpSession;\n21: \n22: import lombok.extern.slf4j.Slf4j;\n23: import org.apache.shiro.SecurityUtils;\n24: import org.jeecg.common.api.vo.Result;\n25: import org.jeecg.common.constant.CommonConstant;\n26: import org.jeecg.common.constant.DataBaseConstant;\n27: import org.jeecg.common.constant.SymbolConstant;\n28: import org.jeecg.common.constant.TenantConstant;\n29: import org.jeecg.common.exception.JeecgBootException;\n30: import org.jeecg.common.system.vo.LoginUser;\n31: import org.jeecg.common.system.vo.SysUserCacheInfo;\n32: import org.jeecg.common.util.DateUtils;\n33: import org.jeecg.common.util.SpringContextUtils;\n34: import org.jeecg.common.util.oConvertUtils;\n35: \n36: /**\n37:  * @Author Scott\n38:  * @Date 2018-07-12 14:23\n39:  * @Desc JWT工具类\n40:  **/\n41: @Slf4j\n42: public class JwtUtil {\n43: \n44: \t/**PC端，Token有效期为7天（Token在reids中缓存时间为两倍）*/\n45: \tpublic static final long EXPIRE_TIME = (7 * 12) * 60 * 60 * 1000L;\n46: \t/**APP端，Token有效期为30天（Token在reids中缓存时间为两倍）*/\n47: \tpublic static final long APP_EXPIRE_TIME = (30 * 12) * 60 * 60 * 1000L;\n48: \tstatic final String WELL_NUMBER = SymbolConstant.WELL_NUMBER + SymbolConstant.LEFT_CURLY_BRACKET;\n49: \n50:     /**\n51:      *\n52:      * @param response\n53:      * @param code\n54:      * @param errorMsg\n55:      */\n56: \tpublic static void responseError(HttpServletResponse response, Integer code, String errorMsg) {\n57: \t\ttry {\n58: \t\t\tResult jsonResult = new Result(code, errorMsg);\n59: \t\t\tjsonResult.setSuccess(false);\n60: \t\t\t\n61: \t\t\t// 设置响应头和内容类型\n62: \t\t\tresponse.setStatus(code);\n63: \t\t\tresponse.setHeader(\"Content-type\", \"text/html;charset=UTF-8\");\n64: \t\t\tresponse.setContentType(\"application/json;charset=UTF-8\");\n65: \t\t\t// 使用 ObjectMapper 序列化为 JSON 字符串\n66: \t\t\tObjectMapper objectMapper = new ObjectMapper();\n67: \t\t\tString json = objectMapper.writeValueAsString(jsonResult);\n68: \t\t\tresponse.getWriter().write(json);\n69: \t\t\tresponse.getWriter().flush();\n70: \t\t} catch (IOException e) {\n71: \t\t\tlog.error(e.getMessage(), e);\n72: \t\t}\n73: \t}\n74: \n75: \t/**\n76: \t * 校验token是否正确\n77: \t *\n78: \t * @param token  密钥\n79: \t * @param secret 用户的密码\n80: \t * @return 是否正确",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysTenantController.java",
      "label": "B",
      "lines": {
        "end": 760,
        "start": 681
      },
      "snippet": "681:         Integer count = relationService.userTenantIzExist(sysUser.getId(),sysTenant.getId());\n682:         if (count == 0) {\n683:             return Result.error(\"此租户下没有当前用户\");\n684:         }\n685:         //验证密码\n686:         String loginPassword = request.getParameter(\"loginPassword\");\n687:         SysUser userById = sysUserService.getById(sysUser.getId());\n688:         String passwordEncode = PasswordUtil.encrypt(sysUser.getUsername(),loginPassword, userById.getSalt());\n689:         if (!passwordEncode.equals(userById.getPassword())) {\n690:             return Result.error(\"密码不正确\");\n691:         }\n692:         //退出登录\n693:         sysTenantService.exitUserTenant(sysUser.getId(),sysUser.getUsername(),String.valueOf(sysTenant.getId()));\n694:         return Result.ok(\"退出租户成功\");\n695:     }\n696: \n697:     /**\n698:      * 变更租户拥有者【低代码应用专用接口】\n699:      * @param userId\n700:      * @return\n701:      */\n702:     @PostMapping(\"/changeOwenUserTenant\")\n703:     public Result<String> changeOwenUserTenant(@RequestParam(\"userId\") String userId,\n704:                                                @RequestParam(\"tenantId\") String tenantId){\n705:         sysTenantService.changeOwenUserTenant(userId,tenantId);\n706:         return Result.ok(\"退出租户成功\");\n707:     }\n708: \n709:     /**\n710:      * 邀请用户到租户,通过手机号匹配 【低代码应用专用接口】\n711:      * @param phone\n712:      * @param departId\n713:      * @return\n714:      */\n715:     @PostMapping(\"/invitationUser\")\n716:     public Result<String> invitationUser(@RequestParam(name=\"phone\") String phone,\n717:                                          @RequestParam(name=\"departId\",defaultValue = \"\") String departId){\n718:         return sysTenantService.invitationUser(phone,departId);\n719:     }\n720: \n721: \n722:     /**\n723:      * 获取 租户产品包-3个默认admin的人员数量\n724:      * @param tenantId\n725:      * @return\n726:      */\n727:     @GetMapping(\"/loadAdminPackCount\")\n728:     public Result<List<TenantPackUserCount>> loadAdminPackCount(@RequestParam(\"tenantId\") Integer tenantId){\n729:         List<TenantPackUserCount> list = sysTenantService.queryTenantPackUserCount(tenantId);\n730:         return Result.ok(list);\n731:     }\n732: \n733:     /**\n734:      * 查询租户产品包信息\n735:      * @param packModel\n736:      * @return\n737:      */\n738:     @GetMapping(\"/getTenantPackInfo\")\n739:     public Result<TenantPackModel> getTenantPackInfo(TenantPackModel packModel){\n740:         TenantPackModel tenantPackModel = sysTenantService.queryTenantPack(packModel);\n741:         return Result.ok(tenantPackModel);\n742:     }\n743: \n744: \n745:     /**\n746:      * 添加用户和产品包的关系数据\n747:      * @param sysTenantPackUser\n748:      * @return\n749:      */\n750:     @PostMapping(\"/addTenantPackUser\")\n751:     public Result<?> addTenantPackUser(@RequestBody SysTenantPackUser sysTenantPackUser){\n752:         sysTenantService.addBatchTenantPackUser(sysTenantPackUser);\n753:         return Result.ok(\"操作成功！\");\n754:     }\n755: \n756:     /**\n757:      * 从产品包移除用户\n758:      * @param sysTenantPackUser\n759:      * @return\n760:      */",
      "span_kind": "sliding_window",
      "symbol": "exitUserTenant"
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-selected resource identifiers, object IDs, tenant IDs, or administrative action targets into sensitive read, write, mutation, deletion, workflow, or administrative operations on the selected resource. Report code paths where the authorization decision is not bound to both the current principal and the exact resource or tenant being affected. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should check ownership or tenant scope before the effect and carry that checked identity into the data access or mutation.",
  "judge_mode": "recall_candidate_pair_advisory"
}

Return JSON only. Do not call tools or run commands.