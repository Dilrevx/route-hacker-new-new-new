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
      "file": "src/main/java/de/rwth/idsg/steve/repository/impl/DataImportExportRepositoryImpl.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.repository.impl;\n20: \n21: import de.rwth.idsg.steve.repository.DataImportExportRepository;\n22: import lombok.RequiredArgsConstructor;\n23: import lombok.extern.slf4j.Slf4j;\n24: import org.apache.commons.lang3.StringUtils;\n25: import org.jooq.CSVFormat;\n26: import org.jooq.Converter;\n27: import org.jooq",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C012",
      "file": "src/main/java/de/rwth/idsg/steve/web/controller/AjaxCallController.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: \n42: /**\n43:  * @author Sevket Goekay <sevketgokay@gmail.com>\n44:  * @since 15.08.2014\n45:  */\n46: @Slf4j\n47: @RequiredArgsConstructor\n48: @Controller\n49: @ResponseBody\n50: @RequestMapping(\n51:         value = \"/manager/ajax/{chargeBoxId}\",\n52:         method = RequestMethod.GET,\n53:         produces = MediaType.APPLICATION_JSON_VALUE)\n54: public class AjaxCallController {\n55: \n56:     private final ObjectMapper objectMapper = createMapper();\n57: \n58:     private final ChargePointService chargePointService;\n59:     private final TransactionService transactionService;\n60:     private final ReservationRepository reservationRepository;\n61:     private final CertificateRepository certificateRepository;\n62: \n63:     // -------------------------------------------------------------------------\n64:     // Paths\n65:     // -------------------------------------------------------------------------\n66: \n67:     private static final String CONNECTOR_IDS_PATH      = \"/connectorIds\";\n68:     private static final String TRANSACTION_IDS_PATH    = \"/transactionIds\";\n69:     private static final String RESERVATION_IDS_PATH    = \"/reservationIds\";\n70:     private static final String CERTIFICATE_ID",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C013",
      "file": "src/main/java/de/rwth/idsg/steve/web/api/ApiControllerAdvice.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.web.api;\n20: \n21: import de.rwth.idsg.steve.SteveException;\n22: import de.rwth.idsg.steve.web.DateTimeEditor;\n23: import lombok.Data;\n24: import lombok.extern.slf4j.Slf4j;\n25: import org.joda.time.DateTime;\n26: import org.springframework.beans.propertyeditors.StringTrimmerEditor;\n27: import org.spring",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C014",
      "file": "src/main/java/de/rwth/idsg/steve/web/GlobalControllerAdvice.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.web;\n20: \n21: import de.rwth.idsg.steve.config.SteveProperties;\n22: import de.rwth.idsg.steve.repository.dto.ChargePointSelect;\n23: import lombok.RequiredArgsConstructor;\n24: import lombok.extern.slf4j.Slf4j;\n25: import org.joda.time.DateTime;\n26: import org.joda.time.LocalDate;\n27: import org.springf",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C015",
      "file": "src/main/java/de/rwth/idsg/steve/config/BeanConfiguration.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81: \n82:         // set standard params\n83:         hc.setJdbcUrl(properties.getUrl());\n84:         hc.setUsername(properties.getUsername());\n85:         hc.setPassword(properties.getPassword());\n86: \n87:         // set non-standard params\n88:         hc.addDataSourceProperty(PropertyKey.cachePrepStmts.getKeyName(), true);\n89:         hc.addDataSourceProperty(PropertyKey.useServerPrepStmts.getKeyName(), true);\n90:         hc.addDataSourceProperty(PropertyKey.prepStmtCacheSize.getKeyName(), 250);\n91:         hc.addDataSourceProperty(PropertyKey.prepStmtCacheSqlLimit.getKeyName(), 2048);\n92:         hc.addDataSourceProperty(PropertyKey.characterEncoding.getKeyName(), \"utf8\");\n93:         hc.addDataSourceProperty(PropertyKey.connectionTimeZone.getKeyName(), SteveProperties.TIME_ZONE_ID);\n94:         hc.addDataSourceProperty(PropertyKey.useSSL.getKeyName(), true);\n95: \n96:         // https://github.com/steve-community/steve/issues/736\n97:         hc.setMaxLifetime(580_000);\n98: \n99:         return new HikariDataSource(hc);\n100:     }\n101: \n102:     /**\n103:      * Can we re-use DSLContext as a Spring bean (singleton)? Yes, the Spring tutorial of\n104:      * Jooq also does it that way, ",
      "span_kind": "sliding_window",
      "symbol": "dataSource"
    },
    {
      "candidate_id": "C016",
      "file": "src/main/java/de/rwth/idsg/steve/config/ApiAuthenticationManager.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.config;\n20: \n21: import tools.jackson.databind.ObjectMapper;\n22: import com.google.common.base.Strings;\n23: import de.rwth.idsg.steve.service.WebUserService;\n24: import de.rwth.idsg.steve.web.api.ApiControllerAdvice;\n25: import lombok.RequiredArgsConstructor;\n26: import lombok.extern.slf4j.Slf4j;\n27: ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C017",
      "file": "src/main/java/de/rwth/idsg/steve/repository/impl/SettingsRepositoryImpl.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * SteVe - SteckdosenVerwaltung - https://github.com/steve-community/steve\n3:  * Copyright (C) 2013-2026 SteVe Community Team\n4:  * All Rights Reserved.\n5:  *\n6:  * This program is free software: you can redistribute it and/or modify\n7:  * it under the terms of the GNU General Public License as published by\n8:  * the Free Software Foundation, either version 3 of the License, or\n9:  * (at your option) any later version.\n10:  *\n11:  * This program is distributed in the hope that it will be useful,\n12:  * but WITHOUT ANY WARRANTY; without even the implied warranty of\n13:  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n14:  * GNU General Public License for more details.\n15:  *\n16:  * You should have received a copy of the GNU General Public License\n17:  * along with this program.  If not, see <https://www.gnu.org/licenses/>.\n18:  */\n19: package de.rwth.idsg.steve.repository.impl;\n20: \n21: import de.rwth.idsg.steve.NotificationFeature;\n22: import de.rwth.idsg.steve.SteveException;\n23: import de.rwth.idsg.steve.repository.SettingsRepository;\n24: import de.rwth.idsg.steve.web.dto.SettingsForm;\n25: import de.rwth.idsg.steve.web.dto.SettingsForm.MailSettings;\n26: i",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C018",
      "file": "src/main/java/de/rwth/idsg/steve/config/SteveProperties.java",
      "lines": {
        "end": 100,
        "start": 41
      },
      "snippet": "41:     // Dummy service path\n42:     public static final String ROUTER_ENDPOINT_PATH = \"/CentralSystemService\";\n43:     // Time zone for the application and database connections\n44:     public static final String TIME_ZONE_ID = \"UTC\";  // or ZoneId.systemDefault().getId();\n45: \n46:     String version;\n47:     Auth auth = new Auth();\n48:     Jooq jooq = new Jooq();\n49:     Ocpp ocpp = new Ocpp();\n50: \n51:     @Data\n52:     public static class Jooq {\n53:         boolean executiveLogging;\n54:     }\n55: \n56:     @Data\n57:     public static class Auth {\n58:         String username;\n59:         String password;\n60:         String webApiKey;\n61:         String webApiSecret;\n62:     }\n63: \n64:     @Data\n65:     public static class Ocpp {\n66:         WsSessionSelectStrategyEnum wsSessionSelectStrategy;\n67:         boolean autoRegisterUnknownStations;\n68:         String chargeBoxIdValidationRegex;\n69:         Protocols enabledProtocols;\n70:         Security security = new Security();\n71: \n72:         @Data\n73:         public static class Protocols {\n74:             Transports v12;\n75:             Transports v15;\n76:             Transports v16;\n77: \n78:             @Data\n79:             publ",
      "span_kind": "sliding_window",
      "symbol": "SteveProperties"
    },
    {
      "candidate_id": "C019",
      "file": "src/main/java/de/rwth/idsg/steve/config/ApiAuthenticationManager.java",
      "lines": {
        "end": 115,
        "start": 41
      },
      "snippet": "41: import jakarta.servlet.http.HttpServletRequest;\n42: import jakarta.servlet.http.HttpServletResponse;\n43: \n44: import java.io.IOException;\n45: \n46: /**\n47:  * @author Sevket Goekay <sevketgokay@gmail.com>\n48:  * @since 17.08.2024\n49:  */\n50: @Slf4j\n51: @Component\n52: @RequiredArgsConstructor\n53: public class ApiAuthenticationManager implements AuthenticationManager, AuthenticationEntryPoint {\n54: \n55:     private final WebUserService webUserService;\n56:     private final PasswordEncoder passwordEncoder;\n57:     private final ObjectMapper jacksonObjectMapper;\n58: \n59:     @Override\n60:     public Authentication authenticate(Authentication authentication) throws AuthenticationException {\n61:         String username = (String) authentication.getPrincipal();\n62:         String apiPassword = (String) authentication.getCredentials();\n63: \n64:         if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(apiPassword)) {\n65:             throw new BadCredentialsException(\"Required parameters missing\");\n66:         }\n67: \n68:         UserDetails userDetails = webUserService.loadUserByUsernameForApi(username);\n69:         if (!areValuesSet(userDetails)) {\n70:             throw new D",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C020",
      "file": "src/main/resources/application.yml",
      "lines": {
        "end": 70,
        "start": 1
      },
      "snippet": "1: spring:\n2:   main:\n3:     banner-mode: off\n4:   profiles.active: @envName@\n5:   application:\n6:     name: steve\n7:   datasource:\n8:     url: jdbc:mysql://${db.ip}:${db.port}/${db.schema}\n9:     username: ${db.user}\n10:     password: ${db.password}\n11:   servlet:\n12:     multipart:\n13:       max-file-size: 1GB\n14:       max-request-size: 1GB\n15:       file-size-threshold: 10GB  # we should not hit this, since 1GB will be the limiting factor earlier\n16: \n17: server:\n18:   address: ${server.host}\n19:   port: ${http.port}\n20:   servlet.context-path: /${context.path}\n21:   compression:\n22:     enabled: ${server.gzip.enabled}\n23:   ssl:\n24:     enabled: ${https.enabled}\n25:     key-store-type:\n26:     key-store: ${keystore.path}\n27:     key-store-password: ${keystore.password}\n28:     trust-store-type:\n29:     trust-store:\n30:     trust-store-password:\n31:     enabled-protocols:\n32:       - TLSv1.2\n33:       - TLSv1.3\n34:     ciphers:\n35:     # or 'need' for strict security profile 3 (mTLS)\n36:     client-auth: want\n37: \n38: steve:\n39:   version: @project.version@\n40:   jooq:\n41:     executive-logging: ${db.sql.logging}\n42:   auth:\n43:     username: ${auth.user}\n44:     password: ${au",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-controlled request values, filters, identifiers, sort fields, expressions, or configuration values into SQL statement strings, JDBC Statement execution, query builders with raw fragments, or database filters. Report code paths where values or structural fragments are concatenated into SQL syntax without parameter binding or a strict allowlist for identifiers and operators. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should use bound parameters for values, allowlist structural SQL fragments, and keep untrusted data out of query syntax.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 2
  }
}

Return JSON only. Do not call tools or run commands.