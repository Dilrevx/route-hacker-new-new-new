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
      "file": "src/main/java/de/rwth/idsg/steve/repository/impl/SettingsRepositoryImpl.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import static de.rwth.idsg.steve.utils.StringUtils.splitByComma;\n42: import static jooq.steve.db.tables.Settings.SETTINGS;\n43: \n44: /**\n45:  * @author Sevket Goekay <sevketgokay@gmail.com>\n46:  * @since 06.11.2015\n47:  */\n48: @Repository\n49: @RequiredArgsConstructor\n50: public class SettingsRepositoryImpl implements SettingsRepository {\n51: \n52:     // Totally unnecessary to specify charset here. We just do it to make findbugs plugin happy.\n53:     //\n54:     private static final String APP_ID = new String(\n55:         Base64.getEncoder().encode(\"SteckdosenVerwaltung\".getBytes(StandardCharsets.UTF_8)),\n56:         StandardCharsets.UTF_8\n57:     );\n58: \n59:     private final DSLContext ctx;\n60: \n61:     @Override\n62:     public SettingsForm getForm() {\n63:         SettingsRecord r = getInternal();\n64: \n65:         var form = new SettingsForm();\n66:         form.setOcppSettings(mapToOcppSettings(r));\n67:         form.setMailSettings(mapToMailSettings(r));\n68:         return form;\n69:     }\n70: \n71:     @Override\n72:     public OcppSettings getOcppSettings() {\n73:         SettingsRecord r = getInternal();\n74:         return mapToOcppSettings(r);\n75:     }\n76: \n77:     @Override\n78",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C002",
      "file": "src/main/java/de/rwth/idsg/steve/web/GlobalControllerAdvice.java",
      "lines": {
        "end": 86,
        "start": 41
      },
      "snippet": "41:  */\n42: @ControllerAdvice(basePackages = \"de.rwth.idsg.steve.web.controller\")\n43: @Slf4j\n44: @RequiredArgsConstructor\n45: public class GlobalControllerAdvice {\n46: \n47:     private final SteveProperties steveProperties;\n48: \n49:     @InitBinder\n50:     public void binder(WebDataBinder binder) {\n51:         BatchInsertConverter batchInsertConverter = new BatchInsertConverter();\n52: \n53:         binder.registerCustomEditor(String.class, new StringTrimmerEditor(true));\n54:         binder.registerCustomEditor(LocalDate.class, new LocalDateEditor());\n55:         binder.registerCustomEditor(DateTime.class, DateTimeEditor.forMvc());\n56:         binder.registerCustomEditor(ChargePointSelect.class, new ChargePointSelectEditor());\n57: \n58:         binder.registerCustomEditor(List.class, \"idList\", batchInsertConverter);\n59:         binder.registerCustomEditor(List.class, \"mailSettings.recipients\", batchInsertConverter);\n60:     }\n61: \n62:     @ExceptionHandler(Exception.class)\n63:     public ModelAndView handleError(HttpServletRequest req, Exception exception) {\n64:         log.error(\"Request: {} raised following exception.\", req.getRequestURL(), exception);\n65: \n66:         ModelAndView ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C003",
      "file": "src/main/java/de/rwth/idsg/steve/service/WebUserService.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81:     @EventListener\n82:     public void afterStart(ContextRefreshedEvent event) {\n83:         if (this.hasUserWithAuthority(\"ADMIN\")) {\n84:             return;\n85:         }\n86: \n87:         var headerVal = steveProperties.getAuth().getWebApiSecret();\n88: \n89:         var encodedApiPassword = StringUtils.isBlank(headerVal)\n90:             ? null\n91:             : passwordEncoder.encode(headerVal);\n92: \n93:         var user = new WebUserRecord()\n94:             .setUsername(steveProperties.getAuth().getUsername())\n95:             .setPassword(passwordEncoder.encode(steveProperties.getAuth().getPassword()))\n96:             .setApiPassword(encodedApiPassword)\n97:             .setEnabled(true)\n98:             .setAuthorities(toJson(AuthorityUtils.createAuthorityList(\"ADMIN\")));\n99: \n100:         webUserRepository.createUser(user);\n101:     }\n102: \n103:     @Override\n104:     public void createUser(UserDetails user) {\n105:         validateUserDetails(user);\n106:         var record = toWebUserRecord(user);\n107:         webUserRepository.createUser(record);\n108:     }\n109: \n110:     @Override\n111:     public void updateUser(UserDetails user) {\n112:         validateUserDetails(user);\n11",
      "span_kind": "sliding_window",
      "symbol": "WebUserService"
    },
    {
      "candidate_id": "C004",
      "file": "src/main/java/de/rwth/idsg/steve/service/WebUserService.java",
      "lines": {
        "end": 263,
        "start": 201
      },
      "snippet": "201:         if (apiPassword == null) {\n202:             apiPassword = \"\";\n203:         }\n204: \n205:         return User\n206:             .withUsername(record.getUsername())\n207:             .password(apiPassword)\n208:             .disabled(!record.getEnabled())\n209:             .authorities(fromJson(record.getAuthorities()))\n210:             .build();\n211:     }\n212: \n213:     private WebUserRecord toWebUserRecord(UserDetails user) {\n214:         return new WebUserRecord()\n215:             .setUsername(user.getUsername())\n216:             .setPassword(user.getPassword())\n217:             .setEnabled(user.isEnabled())\n218:             .setAuthorities(toJson(user.getAuthorities()));\n219:     }\n220: \n221:     private String[] fromJson(JSON jsonArray) {\n222:         return jacksonObjectMapper.readValue(jsonArray.data(), String[].class);\n223:     }\n224: \n225:     private JSON toJson(Collection<? extends GrantedAuthority> authorities) {\n226:         Collection<String> auths = authorities.stream()\n227:             .map(GrantedAuthority::getAuthority)\n228:             .sorted() // keep a stable order of entries\n229:             .collect(Collectors.toCollection(LinkedHashSet::new)); // pre",
      "span_kind": "sliding_window",
      "symbol": "loadUserByUsernameForApiInternal"
    },
    {
      "candidate_id": "C005",
      "file": "src/main/java/de/rwth/idsg/steve/service/WebUserService.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import org.springframework.security.provisioning.JdbcUserDetailsManager;\n42: import org.springframework.security.provisioning.UserDetailsManager;\n43: import org.springframework.stereotype.Service;\n44: import org.springframework.util.Assert;\n45: import tools.jackson.databind.ObjectMapper;\n46: \n47: import java.util.Collection;\n48: import java.util.Collections;\n49: import java.util.LinkedHashSet;\n50: import java.util.concurrent.ExecutionException;\n51: import java.util.concurrent.TimeUnit;\n52: import java.util.stream.Collectors;\n53: \n54: import static org.springframework.security.authentication.UsernamePasswordAuthenticationToken.authenticated;\n55: import static org.springframework.security.core.context.SecurityContextHolder.getContextHolderStrategy;\n56: \n57: /**\n58:  * Inspired by {@link org.springframework.security.provisioning.JdbcUserDetailsManager}\n59:  *\n60:  * @author Sevket Goekay <sevketgokay@gmail.com>\n61:  * @since 15.08.2024\n62:  */\n63: @Service\n64: @RequiredArgsConstructor\n65: public class WebUserService implements UserDetailsManager {\n66: \n67:     // Because Guava's cache does not accept a null value\n68:     private static final UserDetails DUMMY_USER = new User(\"#\", ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C006",
      "file": "src/main/java/de/rwth/idsg/steve/service/WebUserService.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.service;\n20: \n21: import com.google.common.cache.Cache;\n22: import com.google.common.cache.CacheBuilder;\n23: import de.rwth.idsg.steve.config.SteveProperties;\n24: import de.rwth.idsg.steve.repository.WebUserRepository;\n25: import jooq.steve.db.tables.records.WebUserRecord;\n26: import lombok.RequiredAr",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C007",
      "file": "src/main/java/de/rwth/idsg/steve/repository/impl/WebUserRepositoryImpl.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.repository.impl;\n20: \n21: import de.rwth.idsg.steve.repository.WebUserRepository;\n22: import jooq.steve.db.tables.records.WebUserRecord;\n23: import lombok.RequiredArgsConstructor;\n24: import lombok.extern.slf4j.Slf4j;\n25: import org.jooq.DSLContext;\n26: import org.jooq.JSON;\n27: import org.springframe",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C008",
      "file": "src/main/java/de/rwth/idsg/steve/config/SteveProperties.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.config;\n20: \n21: import de.rwth.idsg.steve.ocpp.ws.custom.WsSessionSelectStrategyEnum;\n22: import lombok.Data;\n23: import org.springframework.boot.context.properties.ConfigurationProperties;\n24: import org.springframework.context.annotation.Configuration;\n25: \n26: /**\n27:  * @author Sevket Goekay <sev",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C009",
      "file": "src/main/java/de/rwth/idsg/steve/service/ChargePointService.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import de.rwth.idsg.steve.web.dto.OcppJsonStatus;\n42: import de.rwth.idsg.steve.web.dto.Statistics;\n43: import lombok.RequiredArgsConstructor;\n44: import lombok.extern.slf4j.Slf4j;\n45: import ocpp.cs._2015._10.RegistrationStatus;\n46: import org.apache.commons.lang3.StringUtils;\n47: import org.joda.time.DateTime;\n48: import org.springframework.security.core.Authentication;\n49: import org.springframework.security.crypto.password.PasswordEncoder;\n50: import org.springframework.stereotype.Service;\n51: import org.springframework.util.CollectionUtils;\n52: \n53: import java.util.ArrayList;\n54: import java.util.Arrays;\n55: import java.util.Collection;\n56: import java.util.Collections;\n57: import java.util.List;\n58: import java.util.Map;\n59: import java.util.Objects;\n60: import java.util.Optional;\n61: import java.util.Set;\n62: import java.util.concurrent.locks.Lock;\n63: import java.util.stream.Collectors;\n64: import java.util.stream.Stream;\n65: \n66: /**\n67:  * @author Sevket Goekay <sevketgokay@gmail.com>\n68:  * @since 29.10.2025\n69:  */\n70: @Slf4j\n71: @Service\n72: @RequiredArgsConstructor\n73: public class ChargePointService {\n74: \n75:     private final UnidentifiedIncomingObjectService ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C010",
      "file": "src/main/java/de/rwth/idsg/steve/ocpp/OcppTransport.java",
      "lines": {
        "end": 56,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.ocpp;\n20: \n21: import lombok.Getter;\n22: import lombok.RequiredArgsConstructor;\n23: \n24: /**\n25:  * @author Sevket Goekay <sevketgokay@gmail.com>\n26:  * @since 24.03.2015\n27:  */\n28: @RequiredArgsConstructor\n29: @Getter\n30: public enum OcppTransport {\n31:     SOAP(\"S\"),  // HTTP with SOAP payloads\n32:",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-controlled request values, filters, identifiers, sort fields, expressions, or configuration values into SQL statement strings, JDBC Statement execution, query builders with raw fragments, or database filters. Report code paths where values or structural fragments are concatenated into SQL syntax without parameter binding or a strict allowlist for identifiers and operators. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should use bound parameters for values, allowlist structural SQL fragments, and keep untrusted data out of query syntax.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 1
  }
}

Return JSON only. Do not call tools or run commands.