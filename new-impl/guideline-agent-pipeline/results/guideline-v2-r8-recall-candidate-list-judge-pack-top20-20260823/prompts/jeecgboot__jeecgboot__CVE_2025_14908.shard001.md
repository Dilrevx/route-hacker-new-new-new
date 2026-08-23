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
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/shiro/filters/JwtFilter.java",
      "lines": {
        "end": 132,
        "start": 81
      },
      "snippet": "81:         JwtToken jwtToken = new JwtToken(token);\n82:         // 提交给realm进行登入，如果错误他会抛出异常并被捕获\n83:         getSubject(request, response).login(jwtToken);\n84:         // 如果没有抛出异常则代表登入成功，返回true\n85:         return true;\n86:     }\n87: \n88:     /**\n89:      * 对跨域提供支持\n90:      */\n91:     @Override\n92:     protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {\n93:         HttpServletRequest httpServletRequest = (HttpServletRequest) request;\n94:         HttpServletResponse httpServletResponse = (HttpServletResponse) response;\n95:         if(allowOrigin){\n96:             httpServletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, httpServletRequest.getHeader(HttpHeaders.ORIGIN));\n97:             // 允许客户端请求方法\n98:             httpServletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS, \"GET,POST,OPTIONS,PUT,DELETE\");\n99:             // 允许客户端提交的Header\n100:             String requestHeaders = httpServletRequest.getHeader(HttpHeaders.ACCESS_CONTROL_REQUEST_HEADERS);\n101:             if (StringUtils.isNotEmpty(requestHeaders)) {\n102:                 httpServletResponse.setHeader(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS, requestHeade",
      "span_kind": "sliding_window",
      "symbol": "executeLogin"
    },
    {
      "candidate_id": "C002",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/Swagger2Config.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81: //     * 需要增加swagger授权回调地址\n82: //     * http://localhost:8888/webjars/springfox-swagger-ui/o2c.html\n83: //     * @return\n84: //     */\n85: //    @Bean\n86: //    SecurityScheme securityScheme() {\n87: //        return new ApiKey(CommonConstant.X_ACCESS_TOKEN, CommonConstant.X_ACCESS_TOKEN, \"header\");\n88: //    }\n89: //    /**\n90: //     * JWT token\n91: //     * @return\n92: //     */\n93: //    private List<Parameter> setHeaderToken() {\n94: //        ParameterBuilder tokenPar = new ParameterBuilder();\n95: //        List<Parameter> pars = new ArrayList<>();\n96: //        tokenPar.name(CommonConstant.X_ACCESS_TOKEN).description(\"token\").modelRef(new ModelRef(\"string\")).parameterType(\"header\").required(false).build();\n97: //        pars.add(tokenPar.build());\n98: //        if(MybatisPlusSaasConfig.OPEN_SYSTEM_TENANT_CONTROL){\n99: //            ParameterBuilder tenantPar = new ParameterBuilder();\n100: //            tenantPar.name(CommonConstant.TENANT_ID).description(\"租户ID\").modelRef(new ModelRef(\"string\")).parameterType(\"header\").required(false).build();\n101: //            pars.add(tenantPar.build());\n102: //        }\n103: //\n104: //        return pars;\n105: //    }\n106: //\n107: //   ",
      "span_kind": "sliding_window",
      "symbol": "Docket"
    },
    {
      "candidate_id": "C003",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/Swagger2Config.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: //package org.jeecg.config;\n2: //\n3: //\n4: //import io.swagger.v3.oas.annotations.Operation;\n5: //import org.jeecg.common.constant.CommonConstant;\n6: //import org.jeecg.config.mybatis.MybatisPlusSaasConfig;\n7: //import org.springframework.beans.BeansException;\n8: //import org.springframework.beans.factory.config.BeanPostProcessor;\n9: //import org.springframework.context.annotation.Bean;\n10: //import org.springframework.context.annotation.Configuration;\n11: //import org.springframework.context.annotation.Import;\n12: //import org.springframework.util.ReflectionUtils;\n13: //import org.springframework.web.bind.annotation.RestController;\n14: //import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;\n15: //import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;\n16: //import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;\n17: //import springfox.bean.validators.configuration.BeanValidatorPluginsConfiguration;\n18: //import springfox.documentation.builders.ApiInfoBuilder;\n19: //import springfox.documentation.builders.ParameterBuilder;\n20: //import springfox.documentation.builders.PathSelectors;\n21: //import springfox",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C004",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/common/exception/JeecgBootExceptionHandler.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package org.jeecg.common.exception;\n2: \n3: import cn.hutool.core.util.ObjectUtil;\n4: import jakarta.annotation.Resource;\n5: import jakarta.servlet.http.HttpServletRequest;\n6: import lombok.extern.slf4j.Slf4j;\n7: import org.apache.commons.lang3.exception.ExceptionUtils;\n8: import org.apache.shiro.SecurityUtils;\n9: import org.apache.shiro.authz.AuthorizationException;\n10: import org.apache.shiro.authz.UnauthorizedException;\n11: import org.jeecg.common.api.dto.LogDTO;\n12: import org.jeecg.common.api.vo.Result;\n13: import org.jeecg.common.constant.CommonConstant;\n14: import org.jeecg.common.constant.enums.ClientTerminalTypeEnum;\n15: import org.jeecg.common.enums.SentinelErrorInfoEnum;\n16: import org.jeecg.common.system.vo.LoginUser;\n17: import org.jeecg.common.util.BrowserUtils;\n18: import org.jeecg.common.util.IpUtils;\n19: import org.jeecg.common.util.SpringContextUtils;\n20: import org.jeecg.common.util.oConvertUtils;\n21: import org.jeecg.modules.base.service.BaseCommonService;\n22: import org.springframework.beans.BeansException;\n23: import org.springframework.dao.DataIntegrityViolationException;\n24: import org.springframework.dao.DuplicateKeyException;\n25: import org.springframewo",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C005",
      "file": "jeecg-boot/jeecg-server-cloud/jeecg-visual/jeecg-cloud-xxljob/src/main/java/com/xxl/job/admin/service/LoginService.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package com.xxl.job.admin.service;\n2: \n3: import com.xxl.job.admin.core.model.XxlJobUser;\n4: import com.xxl.job.admin.core.util.CookieUtil;\n5: import com.xxl.job.admin.core.util.I18nUtil;\n6: import com.xxl.job.admin.core.util.JacksonUtil;\n7: import com.xxl.job.admin.dao.XxlJobUserDao;\n8: import com.xxl.job.core.biz.model.ReturnT;\n9: import org.springframework.context.annotation.Configuration;\n10: import org.springframework.util.DigestUtils;\n11: \n12: import jakarta.annotation.Resource;\n13: import jakarta.servlet.http.HttpServletRequest;\n14: import jakarta.servlet.http.HttpServletResponse;\n15: import java.math.BigInteger;\n16: \n17: /**\n18:  * @author xuxueli 2019-05-04 22:13:264\n19:  */\n20: @Configuration\n21: public class LoginService {\n22: \n23:     public static final String LOGIN_IDENTITY_KEY = \"XXL_JOB_LOGIN_IDENTITY\";\n24: \n25:     @Resource\n26:     private XxlJobUserDao xxlJobUserDao;\n27: \n28: \n29:     private String makeToken(XxlJobUser xxlJobUser){\n30:         String tokenJson = JacksonUtil.writeValueAsString(xxlJobUser);\n31:         String tokenHex = new BigInteger(tokenJson.getBytes()).toString(16);\n32:         return tokenHex;\n33:     }\n34:     private XxlJobUser parseToke",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C006",
      "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/openapi/controller/OpenApiController.java",
      "lines": {
        "end": 280,
        "start": 201
      },
      "snippet": "201: \n202:     /**\n203:      * 生成接口访问令牌 Token\n204:      *\n205:      * @param USERNAME\n206:      * @param PASSWORD\n207:      * @return\n208:      */\n209:     private String getToken(String USERNAME, String PASSWORD) {\n210:         String token = JwtUtil.sign(USERNAME, PASSWORD, CommonConstant.CLIENT_TYPE_PC);\n211:         redisUtil.set(CommonConstant.PREFIX_USER_TOKEN + token, token);\n212:         redisUtil.expire(CommonConstant.PREFIX_USER_TOKEN + token, 60);\n213:         return token;\n214:     }\n215: \n216: \n217:     @GetMapping(\"/json\")\n218:     public SwaggerModel swaggerModel() {\n219: \n220:         SwaggerModel swaggerModel = new SwaggerModel();\n221:         swaggerModel.setSwagger(\"2.0\");\n222:         swaggerModel.setInfo(swaggerInfo());\n223:         swaggerModel.setHost(\"jeecg.com\");\n224:         swaggerModel.setBasePath(\"/jeecg-boot\");\n225:         swaggerModel.setSchemes(Lists.newArrayList(\"http\", \"https\"));\n226: \n227:         SwaggerTag swaggerTag = new SwaggerTag();\n228:         swaggerTag.setName(\"openapi\");\n229:         swaggerModel.setTags(Lists.newArrayList(swaggerTag));\n230: \n231:         pathsAndDefinitions(swaggerModel);\n232: \n233:         return swaggerModel;\n234:  ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C007",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/Swagger2Config.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: //@Import(BeanValidatorPluginsConfiguration.class)\n42: //public class Swagger2Config implements WebMvcConfigurer {\n43: //\n44: //    /**\n45: //     *\n46: //     * 显示swagger-ui.html文档展示页，还必须注入swagger资源：\n47: //     *\n48: //     * @param registry\n49: //     */\n50: //    @Override\n51: //    public void addResourceHandlers(ResourceHandlerRegistry registry) {\n52: //        registry.addResourceHandler(\"swagger-ui.html\").addResourceLocations(\"classpath:/META-INF/resources/\");\n53: //        registry.addResourceHandler(\"doc.html\").addResourceLocations(\"classpath:/META-INF/resources/\");\n54: //        registry.addResourceHandler(\"/webjars/**\").addResourceLocations(\"classpath:/META-INF/resources/webjars/\");\n55: //    }\n56: //\n57: //    /**\n58: //     * swagger2的配置文件，这里可以配置swagger2的一些基本的内容，比如扫描的包等等\n59: //     *\n60: //     * @return Docket\n61: //     */\n62: //    @Bean(value = \"defaultApi2\")\n63: //    public Docket defaultApi2() {\n64: //        return new Docket(DocumentationType.SWAGGER_2)\n65: //                .apiInfo(apiInfo())\n66: //                .select()\n67: //                //此包路径下的类，才生成接口文档\n68: //                .apis(RequestHandlerSelectors.basePackage(\"org.jeecg\"))\n69: //        ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C008",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/common/system/util/JwtUtil.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package org.jeecg.common.system.util;\n2: \n3: import com.auth0.jwt.JWT;\n4: import com.auth0.jwt.JWTVerifier;\n5: import com.auth0.jwt.algorithms.Algorithm;\n6: import com.auth0.jwt.exceptions.JWTDecodeException;\n7: import com.auth0.jwt.interfaces.DecodedJWT;\n8: import com.fasterxml.jackson.databind.ObjectMapper;\n9: import com.google.common.base.Joiner;\n10: \n11: import java.io.IOException;\n12: import java.io.OutputStream;\n13: import java.util.Date;\n14: import java.util.Objects;\n15: import java.util.stream.Collectors;\n16: \n17: import jakarta.servlet.ServletResponse;\n18: import jakarta.servlet.http.HttpServletRequest;\n19: import jakarta.servlet.http.HttpServletResponse;\n20: import jakarta.servlet.http.HttpSession;\n21: \n22: import lombok.extern.slf4j.Slf4j;\n23: import org.apache.shiro.SecurityUtils;\n24: import org.jeecg.common.api.vo.Result;\n25: import org.jeecg.common.constant.CommonConstant;\n26: import org.jeecg.common.constant.DataBaseConstant;\n27: import org.jeecg.common.constant.SymbolConstant;\n28: import org.jeecg.common.constant.TenantConstant;\n29: import org.jeecg.common.exception.JeecgBootException;\n30: import org.jeecg.common.system.vo.LoginUser;\n31: import org.jeecg.common.s",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C009",
      "file": "jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/SysUserOnlineController.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package org.jeecg.modules.system.controller;\n2: \n3: import com.baomidou.mybatisplus.extension.plugins.pagination.Page;\n4: import jakarta.annotation.Resource;\n5: import lombok.extern.slf4j.Slf4j;\n6: import org.apache.commons.lang.StringUtils;\n7: import org.apache.shiro.SecurityUtils;\n8: import org.apache.shiro.authz.annotation.RequiresPermissions;\n9: import org.jeecg.common.api.vo.Result;\n10: import org.jeecg.common.constant.CacheConstant;\n11: import org.jeecg.common.constant.CommonConstant;\n12: import org.jeecg.common.system.util.JwtUtil;\n13: import org.jeecg.common.system.vo.LoginUser;\n14: import org.jeecg.common.util.RedisUtil;\n15: import org.jeecg.common.util.oConvertUtils;\n16: import org.jeecg.modules.base.service.BaseCommonService;\n17: import org.jeecg.modules.system.service.ISysUserService;\n18: import org.jeecg.modules.system.service.impl.SysBaseApiImpl;\n19: import org.jeecg.modules.system.vo.SysUserOnlineVO;\n20: import org.springframework.beans.BeanUtils;\n21: import org.springframework.beans.factory.annotation.Autowired;\n22: import org.springframework.data.redis.core.RedisTemplate;\n23: import org.springframework.web.bind.annotation.*;\n24: \n25: import java.util.ArrayList;\n",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C010",
      "file": "jeecg-boot/jeecg-boot-base-core/src/main/java/org/jeecg/config/shiro/ShiroRealm.java",
      "lines": {
        "end": 239,
        "start": 161
      },
      "snippet": "161:                     //========================================================================\n162:                     // 查询用户信息（如果租户不匹配从数据库中重新查询一次用户信息）\n163:                     String loginUserKey = CacheConstant.SYS_USERS_CACHE + \"::\" + username;\n164:                     redisUtil.del(loginUserKey);\n165:                     LoginUser loginUserFromDb = commonApi.getUserByName(username);\n166:                     if (oConvertUtils.isNotEmpty(loginUserFromDb.getRelTenantIds())) {\n167:                         String[] newArray = loginUserFromDb.getRelTenantIds().split(\",\");\n168:                         if (oConvertUtils.isIn(contextTenantId, newArray)) { \n169:                             isAuthorization = true;\n170:                         }\n171:                     }\n172:                     //========================================================================\n173: \n174:                     //*********************************************\n175:                     if(!isAuthorization){\n176:                         log.info(\"租户异常——登录租户：\" + contextTenantId);\n177:                         log.info(\"租户异常——用户拥有租户组：\" + userTenantIds);\n178:                         throw new Authenti",
      "span_kind": "sliding_window",
      "symbol": "AuthenticationException"
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-selected resource identifiers, object IDs, tenant IDs, or administrative action targets into sensitive read, write, mutation, deletion, workflow, or administrative operations on the selected resource. Report code paths where the authorization decision is not bound to both the current principal and the exact resource or tenant being affected. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should check ownership or tenant scope before the effect and carry that checked identity into the data access or mutation.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 1
  }
}

Return JSON only. Do not call tools or run commands.