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
      "file": "src/main/java/de/rwth/idsg/steve/config/ApiAuthenticationManager.java",
      "label": "A",
      "lines": {
        "end": 115,
        "start": 41
      },
      "snippet": "41: import jakarta.servlet.http.HttpServletRequest;\n42: import jakarta.servlet.http.HttpServletResponse;\n43: \n44: import java.io.IOException;\n45: \n46: /**\n47:  * @author Sevket Goekay <sevketgokay@gmail.com>\n48:  * @since 17.08.2024\n49:  */\n50: @Slf4j\n51: @Component\n52: @RequiredArgsConstructor\n53: public class ApiAuthenticationManager implements AuthenticationManager, AuthenticationEntryPoint {\n54: \n55:     private final WebUserService webUserService;\n56:     private final PasswordEncoder passwordEncoder;\n57:     private final ObjectMapper jacksonObjectMapper;\n58: \n59:     @Override\n60:     public Authentication authenticate(Authentication authentication) throws AuthenticationException {\n61:         String username = (String) authentication.getPrincipal();\n62:         String apiPassword = (String) authentication.getCredentials();\n63: \n64:         if (Strings.isNullOrEmpty(username) || Strings.isNullOrEmpty(apiPassword)) {\n65:             throw new BadCredentialsException(\"Required parameters missing\");\n66:         }\n67: \n68:         UserDetails userDetails = webUserService.loadUserByUsernameForApi(username);\n69:         if (!areValuesSet(userDetails)) {\n70:             throw new DisabledException(\"The user does not exist, exists but is disabled or has API access disabled.\");\n71:         }\n72: \n73:         boolean match = passwordEncoder.matches(apiPassword, userDetails.getPassword());\n74:         if (!match) {\n75:             throw new BadCredentialsException(\"Invalid password\");\n76:         }\n77: \n78:         return UsernamePasswordAuthenticationToken.authenticated(\n79:             authentication.getPrincipal(),\n80:             authentication.getCredentials(),\n81:             userDetails.getAuthorities()\n82:         );\n83:     }\n84: \n85:     @Override\n86:     public void commence(HttpServletRequest request,\n87:                          HttpServletResponse response,\n88:                          AuthenticationException authException) throws IOException, ServletException {\n89:         HttpStatus status = HttpStatus.UNAUTHORIZED;\n90: \n91:         var apiResponse = ApiControllerAdvice.createResponse(\n92:             request.getRequestURL().toString(),\n93:             status,\n94:             authException.getMessage()\n95:         );\n96: \n97:         response.setStatus(status.value());\n98:         response.setContentType(MediaType.APPLICATION_JSON_VALUE);\n99:         response.getWriter().print(jacksonObjectMapper.writeValueAsString(apiResponse));\n100:     }\n101: \n102:     private static boolean areValuesSet(UserDetails userDetails) {\n103:         if (userDetails == null) {\n104:             return false;\n105:         }\n106:         if (!userDetails.isEnabled()) {\n107:             return false;\n108:         }\n109:         if (Strings.isNullOrEmpty(userDetails.getPassword())) {\n110:             return false;\n111:         }\n112:         return true;\n113:     }\n114: \n115: }",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "file": "src/main/java/de/rwth/idsg/steve/service/CentralSystemService16_Service.java",
      "label": "B",
      "lines": {
        "end": 240,
        "start": 161
      },
      "snippet": "161: \n162:         if (parameters.getStatus() == ChargePointStatus.FAULTED) {\n163:             applicationEventPublisher.publishEvent(new OcppStationStatusFailure(\n164:                     chargeBoxIdentity, parameters.getConnectorId(), parameters.getErrorCode().value()));\n165:         }\n166: \n167:          if (parameters.getStatus() == ChargePointStatus.SUSPENDED_EV) {\n168:             applicationEventPublisher.publishEvent(new OcppStationStatusSuspendedEV(\n169:                     chargeBoxIdentity, parameters.getConnectorId(), parameters.getTimestamp()));\n170:         }\n171: \n172:         return new StatusNotificationResponse();\n173:     }\n174: \n175:     public MeterValuesResponse meterValues(MeterValuesRequest parameters, String chargeBoxIdentity) {\n176:         Integer transactionId = getTransactionId(parameters);\n177: \n178:         ocppServerRepository.insertMeterValues(\n179:                 chargeBoxIdentity,\n180:                 parameters.getMeterValue(),\n181:                 parameters.getConnectorId(),\n182:                 transactionId\n183:         );\n184: \n185:         return new MeterValuesResponse();\n186:     }\n187: \n188:     public DiagnosticsStatusNotificationResponse diagnosticsStatusNotification(\n189:             DiagnosticsStatusNotificationRequest parameters, String chargeBoxIdentity) {\n190:         String status = parameters.getStatus().value();\n191:         ocppServerRepository.updateChargeboxDiagnosticsStatus(chargeBoxIdentity, status);\n192:         return new DiagnosticsStatusNotificationResponse();\n193:     }\n194: \n195:     public StartTransactionResponse startTransaction(StartTransactionRequest parameters, String chargeBoxIdentity) {\n196:         // Get the authorization info of the user, before making tx changes (will affectAuthorizationStatus)\n197:         IdTagInfo info = ocppTagService.getIdTagInfo(\n198:                 parameters.getIdTag(),\n199:                 true,\n200:                 chargeBoxIdentity,\n201:                 parameters.getConnectorId(),\n202:                 () -> new IdTagInfo().withStatus(AuthorizationStatus.INVALID) // IdTagInfo is required\n203:         );\n204: \n205:         InsertTransactionParams params =\n206:                 InsertTransactionParams.builder()\n207:                                        .chargeBoxId(chargeBoxIdentity)\n208:                                        .connectorId(parameters.getConnectorId())\n209:                                        .idTag(parameters.getIdTag())\n210:                                        .startTimestamp(parameters.getTimestamp())\n211:                                        .startMeterValue(Integer.toString(parameters.getMeterStart()))\n212:                                        .reservationId(parameters.getReservationId())\n213:                                        .eventTimestamp(DateTime.now())\n214:                                        .build();\n215: \n216:         int transactionId = ocppServerRepository.insertTransaction(params);\n217: \n218:         applicationEventPublisher.publishEvent(new OcppTransactionStarted(transactionId, params));\n219: \n220:         return new StartTransactionResponse()\n221:                 .withIdTagInfo(info)\n222:                 .withTransactionId(transactionId);\n223:     }\n224: \n225:     public StopTransactionResponse stopTransaction(StopTransactionRequest parameters, String chargeBoxIdentity) {\n226:         int transactionId = parameters.getTransactionId();\n227:         String stopReason = parameters.isSetReason() ? parameters.getReason().value() : null;\n228: \n229:         // Get the authorization info of the user, before making tx changes (will affectAuthorizationStatus)\n230:         IdTagInfo idTagInfo = ocppTagService.getIdTagInfo(\n231:                 parameters.getIdTag(),\n232:                 false,\n233:                 chargeBoxIdentity,\n234:                 null,\n235:                 () -> null\n236:         );\n237: \n238:         UpdateTransactionParams params =\n239:                 U",
      "span_kind": "sliding_window",
      "symbol": "statusNotification"
    }
  ],
  "guideline": "HCVR type: authorization_bypass\nGuideline: Trace attacker-controlled request values, filters, identifiers, sort fields, expressions, or configuration values into SQL statement strings, JDBC Statement execution, query builders with raw fragments, or database filters. Report code paths where values or structural fragments are concatenated into SQL syntax without parameter binding or a strict allowlist for identifiers and operators. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 1 historical CVE example(s), not as a project-specific signature. A safe implementation should use bound parameters for values, allowlist structural SQL fragments, and keep untrusted data out of query syntax.",
  "judge_mode": "recall_candidate_pair_advisory"
}

Return JSON only. Do not call tools or run commands.