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
      "file": "api/pom.xml",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41:         <jakarta-annotation.version>2.1.1</jakarta-annotation.version>\n42:         <jsr305.version>3.0.2</jsr305.version>\n43:         <junit.version>4.13.2</junit.version>\n44:         <com.github.jknack.handlebars.version>4.4.0</com.github.jknack.handlebars.version>\n45:     </properties>\n46: \n47:     <dependencies>\n48:         <dependency>\n49:             <groupId>com.okta.commons</groupId>\n50:             <artifactId>okta-config-check</artifactId>\n51:         </dependency>\n52:         <dependency>\n53:             <groupId>com.okta.commons</groupId>\n54:             <artifactId>okta-http-api</artifactId>\n55:         </dependency>\n56:         <dependency>\n57:             <groupId>com.okta.commons</groupId>\n58:             <artifactId>okta-commons-lang</artifactId>\n59:         </dependency>\n60:         <dependency>\n61:             <groupId>org.slf4j</groupId>\n62:             <artifactId>slf4j-api</artifactId>\n63:         </dependency>\n64: \n65:         <!-- Swagger annotations -->\n66:         <dependency>\n67:             <groupId>io.swagger</groupId>\n68:             <artifactId>swagger-annotations</artifactId>\n69:             <version>${swagger-annotations.version}</version>\n70:   ",
      "span_kind": "sliding_window",
      "symbol": "API"
    },
    {
      "candidate_id": "C012",
      "file": "api/pom.xml",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81:             <groupId>org.apache.httpcomponents.client5</groupId>\n82:             <artifactId>httpclient5</artifactId>\n83:         </dependency>\n84: \n85:         <!-- JSON processing: Jackson -->\n86:         <dependency>\n87:             <groupId>com.fasterxml.jackson.core</groupId>\n88:             <artifactId>jackson-core</artifactId>\n89:             <version>${jackson.version}</version>\n90:         </dependency>\n91:         <dependency>\n92:             <groupId>com.fasterxml.jackson.core</groupId>\n93:             <artifactId>jackson-annotations</artifactId>\n94:             <version>${jackson.version}</version>\n95:         </dependency>\n96:         <dependency>\n97:             <groupId>com.fasterxml.jackson.core</groupId>\n98:             <artifactId>jackson-databind</artifactId>\n99:             <version>${jackson.version}</version>\n100:         </dependency>\n101:         <dependency>\n102:             <groupId>com.fasterxml.jackson.jaxrs</groupId>\n103:             <artifactId>jackson-jaxrs-json-provider</artifactId>\n104:             <version>${jackson.version}</version>\n105:         </dependency>\n106:         <dependency>\n107:             <groupId>org.openapitools</groupId>\n108: ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C013",
      "file": "impl/src/main/java/com/okta/sdk/impl/oauth2/DPoPInterceptor.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import java.security.PrivateKey;\n42: import java.security.PublicKey;\n43: import java.time.Instant;\n44: import java.util.Date;\n45: import java.util.UUID;\n46: \n47: import static com.okta.sdk.impl.oauth2.AccessTokenRetrieverServiceImpl.TOKEN_URI;\n48: \n49: /**\n50:  * Interceptor that handle DPoP handshake during auth and adds DPoP header to regular requests.\n51:  * It is always enabled, but is only active when a DPoP error is received during auth.\n52:  *\n53:  * @see <a href=\"https://developer.okta.com/docs/guides/dpop/oktaresourceserver/main/\">documentation</a>\n54:  */\n55: public class DPoPInterceptor implements ExecChainHandler {\n56: \n57:     private static final Logger log = LoggerFactory.getLogger(DPoPInterceptor.class);\n58: \n59:     private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();\n60:     private static final String DPOP_HEADER = \"DPoP\";\n61:     //nonce is valid for 24 hours, but can only refresh it when doing a token request => start refreshing after 22 hours\n62:     private static final int NONCE_VALID_SECONDS = 60 * 60 * 22;\n63:     //MessageDigest is not thread-safe, need one per thread\n64:     private static final ThreadLocal<MessageDigest> SHA256 = Th",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C014",
      "file": "impl/src/main/java/com/okta/sdk/impl/oauth2/AccessTokenRetrieverServiceImpl.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2020-Present Okta, Inc.\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  *     http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: package com.okta.sdk.impl.oauth2;\n17: \n18: import com.fasterxml.jackson.core.type.TypeReference;\n19: import com.okta.commons.http.MediaType;\n20: import com.okta.commons.http.authc.DisabledAuthenticator;\n21: import com.okta.commons.lang.Assert;\n22: import com.okta.commons.lang.Strings;\n23: import com.okta.sdk.client.AuthenticationScheme;\n24: import com.okta.sdk.client.AuthorizationMode;\n25: import com.okta.sdk.impl.api.DefaultClientCredentialsResolver;\n26: import com.okta.sdk.impl.config.ClientConfiguration;\n27: import com.okta.sdk.impl.u",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C015",
      "file": "pom.xml",
      "lines": {
        "end": 200,
        "start": 121
      },
      "snippet": "121:             </dependency>\n122:             <dependency>\n123:                 <groupId>org.slf4j</groupId>\n124:                 <artifactId>jcl-over-slf4j</artifactId>\n125:                 <version>${slf4j.version}</version>\n126:             </dependency>\n127:             <dependency>\n128:                 <groupId>ch.qos.logback</groupId>\n129:                 <artifactId>logback-classic</artifactId>\n130:                 <version>1.3.14</version>\n131:             </dependency>\n132: \n133:             <!-- Bouncy Castle -->\n134:             <dependency>\n135:                 <groupId>org.bouncycastle</groupId>\n136:                 <artifactId>bcprov-jdk18on</artifactId>\n137:                 <version>${bouncycastle.version}</version>\n138:             </dependency>\n139: \n140:             <dependency>\n141:                 <groupId>org.bouncycastle</groupId>\n142:                 <artifactId>bcpkix-jdk18on</artifactId>\n143:                 <version>${bouncycastle.version}</version>\n144:             </dependency>\n145: \n146:             <!-- JJWT -->\n147:             <dependency>\n148:                 <groupId>io.jsonwebtoken</groupId>\n149:                 <artifactId>jjwt-api</artifactId>",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C016",
      "file": "impl/src/main/java/com/okta/sdk/impl/client/DefaultClientBuilder.java",
      "lines": {
        "end": 520,
        "start": 441
      },
      "snippet": "441:     }\n442: \n443:     /**\n444:      * @since 1.6.0\n445:      */\n446:     private void validateOAuth2ClientConfig(ClientConfiguration clientConfiguration) {\n447:         Assert.notNull(clientConfiguration.getClientId(), \"clientId cannot be null\");\n448:         Assert.isTrue(clientConfiguration.getScopes() != null && !clientConfiguration.getScopes().isEmpty(),\n449:             \"At least one scope is required\");\n450:         String privateKey = clientConfiguration.getPrivateKey();\n451:         String oAuth2AccessToken = clientConfiguration.getOAuth2AccessToken();\n452:         UnaryOperator<byte[]> jwtSigner = clientConfiguration.getJwtSigner();\n453:         String jwtSigningAlgorithm = clientConfiguration.getJwtSigningAlgorithm();\n454:         Assert.isTrue(Objects.nonNull(privateKey) || Objects.nonNull(oAuth2AccessToken)\n455:                       || Objects.nonNull(jwtSigner) && Objects.nonNull(jwtSigningAlgorithm),\n456:                           \"Either Private Key (or) Access Token (or) JWT Signer + Algorithm\" +\n457:                           \" must be supplied for OAuth2 Authentication mode\");\n458: \n459:         if (Strings.hasText(privateKey) && !ConfigUtil.hasPrivateKeyCont",
      "span_kind": "sliding_window",
      "symbol": "setProxy"
    },
    {
      "candidate_id": "C017",
      "file": "impl/src/main/java/com/okta/sdk/impl/client/DefaultClientBuilder.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81: import java.io.*;\n82: import java.nio.charset.StandardCharsets;\n83: import java.nio.file.*;\n84: import java.security.PrivateKey;\n85: import java.util.*;\n86: import java.util.concurrent.TimeUnit;\n87: import java.util.function.UnaryOperator;\n88: import java.util.stream.Collectors;\n89: \n90: /**\n91:  * <p>The default {@link ClientBuilder} implementation. This looks for configuration files\n92:  * in the following locations and order of precedence (last one wins).</p>\n93:  * <ul>\n94:  * <li>classpath:com/okta/sdk/config/okta.properties</li>\n95:  * <li>classpath:com/okta/sdk/config/okta.yaml</li>\n96:  * <li>classpath:okta.properties</li>\n97:  * <li>classpath:okta.yaml</li>\n98:  * <li>~/.okta/okta.yaml</li>\n99:  * <li>Environment Variables (with dot notation converted to uppercase + underscores)</li>\n100:  * <li>System Properties</li>\n101:  * <li>Programmatically</li>\n102:  * </ul>\n103:  *\n104:  * Please be aware that, in general, loading secrets (such as api-keys or PEM-content) from environment variables\n105:  * or system properties can lead to those secrets being leaked.\n106:  *\n107:  * @since 0.5.0\n108:  */\n109: public class DefaultClientBuilder implements ClientBuilder {\n110:     ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C018",
      "file": "api/src/main/java/com/okta/sdk/client/MultiThreadingWarningUtil.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2025-Present Okta, Inc.\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  *     http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: package com.okta.sdk.client;\n17: \n18: import org.slf4j.Logger;\n19: import org.slf4j.LoggerFactory;\n20: \n21: import java.util.Set;\n22: import java.util.concurrent.ConcurrentHashMap;\n23: import java.util.concurrent.atomic.AtomicBoolean;\n24: import java.util.concurrent.atomic.AtomicInteger;\n25: \n26: /**\n27:  * Utility class to detect and warn about multi-threaded usage of the Okta SDK.\n28:  * \n29:  * <p>The Okta SDK stores per-thread pagination state keyed by thread ID. When multiple threads\n30:  * use the same ApiClient instance, this can ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C019",
      "file": "impl/src/main/java/com/okta/sdk/impl/oauth2/DPoPInterceptor.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81:         if (tokenRequest && nonce != null && nonceValidUntil.isBefore(Instant.now())) {\n82:             log.debug(\"DPoP nonce expired, will refresh it\");\n83:             nonce = null;\n84:             nonceValidUntil = null;\n85:         }\n86:         if (jwk != null) {\n87:             processRequest(request, tokenRequest);\n88:         }\n89:         ClassicHttpResponse response = execChain.proceed(request, scope);\n90:         if (tokenRequest) {\n91:             if (response.getCode() == 200 && nonce != null) {\n92:                 log.info(\"DPoP handshake successful\");\n93:             }\n94:             if (response.getCode() == 400) {\n95:                 JsonNode errorBody = OBJECT_MAPPER.readTree(response.getEntity().getContent());\n96:                 Header nonceHeader = response.getFirstHeader(\"dpop-nonce\");\n97:                 DPopHandshakeState handshakeState = handleHandshakeResponse(errorBody.get(\"error\"), nonceHeader);\n98:                 throw new DPoPHandshakeException(handshakeState, OBJECT_MAPPER.writeValueAsString(errorBody));\n99:             }\n100:         }\n101:         return response;\n102:     }\n103: \n104:     private void processRequest(HttpRequest request, boole",
      "span_kind": "sliding_window",
      "symbol": "execute"
    },
    {
      "candidate_id": "C020",
      "file": "examples/quickstart/src/main/java/quickstart/ReadmeSnippets.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import java.util.*;\n42: import java.util.concurrent.TimeUnit;\n43: \n44: import static com.okta.sdk.cache.Caches.forResource;\n45: \n46: /**\n47:  * Example snippets used for this projects README.md.\n48:  * <p>\n49:  * Manually run {@code mvn okta-code-snippet:snip} after changing this file to update the README.md.\n50:  */\n51: @SuppressWarnings({\"unused\"})\n52: public class ReadmeSnippets {\n53: \n54:     private static final Logger log = LoggerFactory.getLogger(ReadmeSnippets.class);\n55: \n56:     private final ApiClient client = Clients.builder().build();\n57:     private static final User user = null;\n58: \n59:     private void createClient() {\n60:         ApiClient client = Clients.builder()\n61:             .setOrgUrl(\"https://{yourOktaDomain}\")  // e.g. https://dev-123456.okta.com\n62:             .setClientCredentials(new TokenClientCredentials(\"{apiToken}\"))\n63:             .build();\n64:     }\n65: \n66:     private void createOAuth2Client() {\n67:         ApiClient client = Clients.builder()\n68:             .setOrgUrl(\"https://{yourOktaDomain}\")  // e.g. https://dev-123456.okta.com\n69:             .setAuthorizationMode(AuthorizationMode.PRIVATE_KEY)\n70:             .setClientId(\"{clien",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: concurrent_object_lifecycle\nGuideline: Trace mutable files, paths, objects, identities, request fields, or shared state that are checked before use into sensitive file, state, permission, memory, or resource effects that depend on the earlier check. Report code paths where the checked value is not stabilized with a handle, lock, transaction, immutable copy, or atomic operation before the effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should bind the check to a stable reference or perform the check and effect under the same atomic operation or synchronization boundary.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 2
  }
}

Return JSON only. Do not call tools or run commands.