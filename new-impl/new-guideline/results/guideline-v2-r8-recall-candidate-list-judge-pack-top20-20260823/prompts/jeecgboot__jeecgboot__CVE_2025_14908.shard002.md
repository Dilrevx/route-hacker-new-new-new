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
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/common/api/dto/OnlineAuthDTO.java",
      "lines": {
        "end": 47,
        "start": 1
      },
      "snippet": "1: package org.jeecg.common.api.dto;\n2: \n3: import lombok.Data;\n4: \n5: import java.io.Serializable;\n6: import java.util.List;\n7: \n8: /**\n9:  * online 拦截器权限判断\n10:  * cloud api 用到的接口传输对象\n11:  * @author: jeecg-boot\n12:  */\n13: @Data\n14: public class OnlineAuthDTO implements Serializable {\n15:     private static final long serialVersionUID = 1771827545416418203L;\n16: \n17: \n18:     /**\n19:      * 用户名\n20:      */\n21:     private String username;\n22: \n23:     /**\n24:      * 可能的请求地址\n25:      */\n26:     private List<String> possibleUrl;\n27: \n28:     /**\n29:      * online开发的菜单地址\n30:      */\n31:     private String onlineFormUrl;\n32: \n33:     /**\n34:      * online工单的地址\n35:      */\n36:     private String onlineWorkOrderUrl;\n37: \n38:     public OnlineAuthDTO(){\n39: \n40:     }\n41: \n42:     public OnlineAuthDTO(String username, List<String> possibleUrl, String onlineFormUrl){\n43:         this.username = username;\n44:         this.possibleUrl = possibleUrl;\n45:         this.onlineFormUrl = onlineFormUrl;\n46:     }\n47: }",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C012",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/shiro/ShiroRealm.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: public class ShiroRealm extends AuthorizingRealm {\n42: \t@Lazy\n43:     @Resource\n44:     private CommonAPI commonApi;\n45: \n46:     @Lazy\n47:     @Resource\n48:     private RedisUtil redisUtil;\n49: \n50:     /**\n51:      * 必须重写此方法，不然Shiro会报错\n52:      */\n53:     @Override\n54:     public boolean supports(AuthenticationToken token) {\n55:         return token instanceof JwtToken;\n56:     }\n57: \n58:     /**\n59:      * 权限信息认证(包括角色以及权限)是用户访问controller的时候才进行验证(redis存储的此处权限信息)\n60:      * 触发检测用户权限时才会调用此方法，例如checkRole,checkPermission\n61:      *\n62:      * @param principals 身份信息\n63:      * @return AuthorizationInfo 权限信息\n64:      */\n65:     @Override\n66:     protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {\n67:         log.debug(\"===============Shiro权限认证开始============ [ roles、permissions]==========\");\n68:         String username = null;\n69:         String userId = null;\n70:         if (principals != null) {\n71:             LoginUser sysUser = (LoginUser) principals.getPrimaryPrincipal();\n72:             username = sysUser.getUsername();\n73:             userId = sysUser.getId();\n74:         }\n75:         SimpleAuthorizationInfo info = new SimpleAuthorizationInf",
      "span_kind": "sliding_window",
      "symbol": "ShiroRealm"
    },
    {
      "candidate_id": "C013",
      "file": "jeecg-boot/jeecg-module-system/jeecg-system-api/jeecg-system-cloud-api/src/main/java/org/jeecg/config/FeignConfig.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: //package org.jeecg.config;\n2: //\n3: //import java.io.IOException;\n4: //import java.util.ArrayList;\n5: //import java.util.Arrays;\n6: //import java.util.List;\n7: //import java.util.SortedMap;\n8: //\n9: //import jakarta.servlet.http.HttpServletRequest;\n10: //\n11: //import org.jeecg.common.config.mqtoken.UserTokenContext;\n12: //import org.jeecg.common.constant.CommonConstant;\n13: //import org.jeecg.common.util.DateUtils;\n14: //import org.jeecg.common.util.PathMatcherUtil;\n15: //import org.jeecg.config.sign.interceptor.SignAuthConfiguration;\n16: //import org.jeecg.config.sign.util.HttpUtils;\n17: //import org.jeecg.config.sign.util.SignUtil;\n18: //import org.springframework.beans.factory.ObjectFactory;\n19: //import org.springframework.boot.autoconfigure.AutoConfigureBefore;\n20: //import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;\n21: //import org.springframework.boot.autoconfigure.http.HttpMessageConverters;\n22: //import org.springframework.cloud.openfeign.FeignAutoConfiguration;\n23: //import org.springframework.cloud.openfeign.support.SpringDecoder;\n24: //import org.springframework.cloud.openfeign.support.SpringEncoder;\n25: //import org.springframework.contex",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C014",
      "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/api/controller/SystemApiController.java",
      "lines": {
        "end": 880,
        "start": 801
      },
      "snippet": "801:     }\n802: \n803:     /**\n804:      * 保存数据日志\n805:      * @param dataLogDto\n806:      */\n807:     @PostMapping(\"/saveDataLog\")\n808:     public void saveDataLog(@RequestBody DataLogDTO dataLogDto){\n809:         this.sysBaseApi.saveDataLog(dataLogDto);\n810:     }\n811: \n812:     /**\n813:      * 更新头像\n814:      * @param loginUser\n815:      * @return\n816:      */\n817:     @PutMapping(\"/updateAvatar\")\n818:     public void updateAvatar(@RequestBody LoginUser loginUser){\n819:         this.sysBaseApi.updateAvatar(loginUser);\n820:     }\n821: \n822:     /**\n823:      * 向app端 websocket推送聊天刷新消息\n824:      * @param userId\n825:      * @return\n826:      */\n827:     @GetMapping(\"/sendAppChatSocket\")\n828:     public void sendAppChatSocket(@RequestParam(name=\"userId\") String userId){\n829:         this.sysBaseApi.sendAppChatSocket(userId);\n830:     }\n831: \n832:     /**\n833:      * 根据roleCode查询角色信息，可逗号分隔多个\n834:      *\n835:      * @param roleCodes\n836:      * @return\n837:      */\n838:     @GetMapping(\"/queryRoleDictByCode\")\n839:     public List<DictModel> queryRoleDictByCode(@RequestParam(name = \"roleCodes\") String roleCodes) {\n840:         return this.sysBaseApi.queryRoleDictByCode(roleCodes);\n841:    ",
      "span_kind": "sliding_window",
      "symbol": "getTemplateContent"
    },
    {
      "candidate_id": "C015",
      "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysUserOnlineController.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41:     @Autowired\n42:     private RedisUtil redisUtil;\n43:     @Autowired\n44:     public RedisTemplate redisTemplate;\n45:     @Autowired\n46:     public ISysUserService userService;\n47:     @Autowired\n48:     private SysBaseApiImpl sysBaseApi;\n49:     @Resource\n50:     private BaseCommonService baseCommonService;\n51: \n52:     @RequiresPermissions(\"system:online:list\")\n53:     @RequestMapping(value = \"/list\", method = RequestMethod.GET)\n54:     public Result<Page<SysUserOnlineVO>> list(@RequestParam(name=\"username\", required=false) String username,\n55:                                               @RequestParam(name=\"pageNo\", defaultValue=\"1\") Integer pageNo,@RequestParam(name=\"pageSize\", defaultValue=\"10\") Integer pageSize) {\n56:         Collection<String> keys = redisUtil.scan(CommonConstant.PREFIX_USER_TOKEN + \"*\");\n57:         List<SysUserOnlineVO> onlineList = new ArrayList<SysUserOnlineVO>();\n58:         for (String key : keys) {\n59:             String token = (String)redisUtil.get(key);\n60:             if (StringUtils.isNotEmpty(token)) {\n61:                 SysUserOnlineVO online = new SysUserOnlineVO();\n62:                 online.setToken(token);\n63:                 //TODO ",
      "span_kind": "sliding_window",
      "symbol": "SysUserOnlineController"
    },
    {
      "candidate_id": "C016",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/vo/Path.java",
      "lines": {
        "end": 29,
        "start": 1
      },
      "snippet": "1: package org.jeecg.config.vo;\n2: \n3: import javax.print.DocFlavor;\n4: \n5: /**\n6:  *\n7:  * @author: scott\n8:  * @date: 2022年04月18日 20:35\n9:  */\n10: public class Path {\n11:     private String upload;\n12:     private String webapp;\n13: \n14:     public String getUpload() {\n15:         return upload;\n16:     }\n17: \n18:     public void setUpload(String upload) {\n19:         this.upload = upload;\n20:     }\n21: \n22:     public String getWebapp() {\n23:         return webapp;\n24:     }\n25: \n26:     public void setWebapp(String webapp) {\n27:         this.webapp = webapp;\n28:     }\n29: }",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C017",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/Swagger2Config.java",
      "lines": {
        "end": 186,
        "start": 121
      },
      "snippet": "121: //                // 作者\n122: //                .contact(new Contact(\"北京国炬信息技术有限公司\",\"www.jeccg.com\",\"jeecgos@163.com\"))\n123: //                .license(\"The Apache License, Version 2.0\")\n124: //                .licenseUrl(\"http://www.apache.org/licenses/LICENSE-2.0.html\")\n125: //                .build();\n126: //    }\n127: //\n128: //    /**\n129: //     * 新增 securityContexts 保持登录状态\n130: //     */\n131: //    private List<SecurityContext> securityContexts() {\n132: //        return new ArrayList(\n133: //                Collections.singleton(SecurityContext.builder()\n134: //                        .securityReferences(defaultAuth())\n135: //                        .forPaths(PathSelectors.regex(\"^(?!auth).*$\"))\n136: //                        .build())\n137: //        );\n138: //    }\n139: //\n140: //    private List<SecurityReference> defaultAuth() {\n141: //        AuthorizationScope authorizationScope = new AuthorizationScope(\"global\", \"accessEverything\");\n142: //        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];\n143: //        authorizationScopes[0] = authorizationScope;\n144: //        return new ArrayList(\n145: //                Collections.singleton(new Secur",
      "span_kind": "sliding_window",
      "symbol": "ApiInfoBuilder"
    },
    {
      "candidate_id": "C018",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/common/system/util/JwtUtil.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: @Slf4j\n42: public class JwtUtil {\n43: \n44: \t/**PC端，Token有效期为7天（Token在reids中缓存时间为两倍）*/\n45: \tpublic static final long EXPIRE_TIME = (7 * 12) * 60 * 60 * 1000L;\n46: \t/**APP端，Token有效期为30天（Token在reids中缓存时间为两倍）*/\n47: \tpublic static final long APP_EXPIRE_TIME = (30 * 12) * 60 * 60 * 1000L;\n48: \tstatic final String WELL_NUMBER = SymbolConstant.WELL_NUMBER + SymbolConstant.LEFT_CURLY_BRACKET;\n49: \n50:     /**\n51:      *\n52:      * @param response\n53:      * @param code\n54:      * @param errorMsg\n55:      */\n56: \tpublic static void responseError(HttpServletResponse response, Integer code, String errorMsg) {\n57: \t\ttry {\n58: \t\t\tResult jsonResult = new Result(code, errorMsg);\n59: \t\t\tjsonResult.setSuccess(false);\n60: \t\t\t\n61: \t\t\t// 设置响应头和内容类型\n62: \t\t\tresponse.setStatus(code);\n63: \t\t\tresponse.setHeader(\"Content-type\", \"text/html;charset=UTF-8\");\n64: \t\t\tresponse.setContentType(\"application/json;charset=UTF-8\");\n65: \t\t\t// 使用 ObjectMapper 序列化为 JSON 字符串\n66: \t\t\tObjectMapper objectMapper = new ObjectMapper();\n67: \t\t\tString json = objectMapper.writeValueAsString(jsonResult);\n68: \t\t\tresponse.getWriter().write(json);\n69: \t\t\tresponse.getWriter().flush();\n70: \t\t} catch (IOException e) {\n71: \t\t\tlog.error(e",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C019",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/shiro/ShiroRealm.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package org.jeecg.config.shiro;\n2: \n3: import lombok.extern.slf4j.Slf4j;\n4: import org.apache.shiro.authc.AuthenticationException;\n5: import org.apache.shiro.authc.AuthenticationInfo;\n6: import org.apache.shiro.authc.AuthenticationToken;\n7: import org.apache.shiro.authc.SimpleAuthenticationInfo;\n8: import org.apache.shiro.authz.AuthorizationInfo;\n9: import org.apache.shiro.authz.SimpleAuthorizationInfo;\n10: import org.apache.shiro.realm.AuthorizingRealm;\n11: import org.apache.shiro.subject.PrincipalCollection;\n12: import org.jeecg.common.api.CommonAPI;\n13: import org.jeecg.common.config.TenantContext;\n14: import org.jeecg.common.constant.CacheConstant;\n15: import org.jeecg.common.constant.CommonConstant;\n16: import org.jeecg.common.system.util.JwtUtil;\n17: import org.jeecg.common.system.vo.LoginUser;\n18: import org.jeecg.common.util.RedisUtil;\n19: import org.jeecg.common.util.SpringContextUtils;\n20: import org.jeecg.common.util.TokenUtils;\n21: import org.jeecg.common.util.oConvertUtils;\n22: import org.jeecg.config.mybatis.MybatisPlusSaasConfig;\n23: import org.springframework.beans.factory.config.BeanDefinition;\n24: import org.springframework.context.annotation.Lazy;\n25: import o",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C020",
      "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/LoginController.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import java.util.*;\n42: import java.util.concurrent.ExecutorService;\n43: import java.util.concurrent.SynchronousQueue;\n44: import java.util.concurrent.TimeUnit;\n45: \n46: /**\n47:  * @Author scott\n48:  * @since 2018-12-17\n49:  */\n50: @RestController\n51: @RequestMapping(\"/sys\")\n52: @Tag(name=\"用户登录\")\n53: @Slf4j\n54: public class LoginController {\n55: \t@Autowired\n56: \tprivate ISysUserService sysUserService;\n57: \t@Autowired\n58: \tprivate ISysPermissionService sysPermissionService;\n59: \t@Autowired\n60: \tprivate SysBaseApiImpl sysBaseApi;\n61: \t@Autowired\n62: \tprivate ISysLogService logService;\n63: \t@Autowired\n64:     private RedisUtil redisUtil;\n65: \t@Autowired\n66:     private ISysDepartService sysDepartService;\n67: \t@Autowired\n68:     private ISysDictService sysDictService;\n69: \t@Resource\n70: \tprivate BaseCommonService baseCommonService;\n71: \t@Autowired\n72: \tprivate JeecgBaseConfig jeecgBaseConfig;\n73: \t\n74: \tprivate final String BASE_CHECK_CODES = \"qwertyuiplkjhgfdsazxcvbnmQWERTYUPLKJHGFDSAZXCVBNM1234567890\";\n75: \t/**\n76: \t * 线程池用于异步发送纪要\n77: \t */\n78: \tpublic static ExecutorService cachedThreadPool = new ShiroThreadPoolExecutor(0, 1024, 60L, TimeUnit.SECONDS, new SynchronousQueue<>());\n7",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-selected resource identifiers, object IDs, tenant IDs, or administrative action targets into sensitive read, write, mutation, deletion, workflow, or administrative operations on the selected resource. Report code paths where the authorization decision is not bound to both the current principal and the exact resource or tenant being affected. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should check ownership or tenant scope before the effect and carry that checked identity into the data access or mutation.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 2
  }
}

Return JSON only. Do not call tools or run commands.