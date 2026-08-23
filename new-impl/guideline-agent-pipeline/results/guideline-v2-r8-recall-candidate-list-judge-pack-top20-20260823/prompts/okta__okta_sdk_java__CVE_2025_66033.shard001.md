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
      "file": "impl/src/main/java/com/okta/sdk/impl/cache/DefaultCache.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2014 Stormpath, Inc.\n3:  * Modifications Copyright 2018 Okta, Inc.\n4:  *\n5:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n6:  * you may not use this file except in compliance with the License.\n7:  * You may obtain a copy of the License at\n8:  *\n9:  *     http://www.apache.org/licenses/LICENSE-2.0\n10:  *\n11:  * Unless required by applicable law or agreed to in writing, software\n12:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n13:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n14:  * See the License for the specific language governing permissions and\n15:  * limitations under the License.\n16:  */\n17: package com.okta.sdk.impl.cache;\n18: \n19: import com.okta.commons.lang.Assert;\n20: import com.okta.sdk.cache.Cache;\n21: import com.okta.sdk.impl.util.SoftHashMap;\n22: import org.slf4j.Logger;\n23: import org.slf4j.LoggerFactory;\n24: \n25: import java.time.Duration;\n26: import java.util.Map;\n27: import java.util.concurrent.atomic.AtomicLong;\n28: \n29: /**\n30:  * A {@code DefaultCache} is a {@link Cache Cache} implementation that uses a backing {@link Map} instance to store\n31:  * and retrieve cache",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C002",
      "file": "api/src/main/java/com/okta/sdk/client/MultiThreadingWarningUtil.java",
      "lines": {
        "end": 256,
        "start": 201
      },
      "snippet": "201:             \"  3. Avoid using the SDK's collection/pagination methods in multi-threaded\\n\" +\n202:             \"     contexts where threads share an ApiClient instance\\n\" +\n203:             \"\\n\" +\n204:             \"For more information, see: https://github.com/okta/okta-sdk-java/issues/1637\\n\" +\n205:             \"================================================================================\\n\",\n206:             threadCount\n207:         );\n208:     }\n209:     \n210:     /**\n211:      * Emits a warning specific to thread pool usage.\n212:      */\n213:     private void emitThreadPoolWarning() {\n214:         log.warn(\n215:             \"\\n\" +\n216:             \"================================================================================\\n\" +\n217:             \"OKTA SDK THREAD POOL WARNING\\n\" +\n218:             \"================================================================================\\n\" +\n219:             \"The Okta SDK has detected thread pool usage (e.g., in a web server or\\n\" +\n220:             \"async framework). This usage pattern has specific concerns:\\n\" +\n221:             \"\\n\" +\n222:             \"THREAD POOL ISSUE:\\n\" +\n223:             \"  - Thread pool threads are re",
      "span_kind": "sliding_window",
      "symbol": "instance"
    },
    {
      "candidate_id": "C003",
      "file": "pom.xml",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81:                 <groupId>com.okta.commons</groupId>\n82:                 <artifactId>okta-config-check</artifactId>\n83:                 <version>${okta.commons.version}</version>\n84:             </dependency>\n85:             <dependency>\n86:                 <groupId>com.okta.commons</groupId>\n87:                 <artifactId>okta-commons-lang</artifactId>\n88:                 <version>${okta.commons.version}</version>\n89:             </dependency>\n90:             <dependency>\n91:                 <groupId>com.okta.commons</groupId>\n92:                 <artifactId>okta-http-api</artifactId>\n93:                 <version>${okta.commons.version}</version>\n94:             </dependency>\n95: \n96:             <dependency>\n97:                 <groupId>javax.annotation</groupId>\n98:                 <artifactId>javax.annotation-api</artifactId>\n99:                 <version>1.3.2</version>\n100:             </dependency>\n101: \n102:             <!-- ITs -->\n103:             <dependency>\n104:                 <groupId>com.okta.sdk</groupId>\n105:                 <artifactId>okta-sdk-integration-tests</artifactId>\n106:                 <version>23.0.1</version>\n107:             </dependency>\n108: \n10",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C004",
      "file": "pom.xml",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: <?xml version=\"1.0\" encoding=\"UTF-8\"?>\n2: <!--\n3:   ~ Copyright 2017 Okta\n4:   ~\n5:   ~ Licensed under the Apache License, Version 2.0 (the \"License\");\n6:   ~ you may not use this file except in compliance with the License.\n7:   ~ You may obtain a copy of the License at\n8:   ~\n9:   ~     http://www.apache.org/licenses/LICENSE-2.0\n10:   ~\n11:   ~ Unless required by applicable law or agreed to in writing, software\n12:   ~ distributed under the License is distributed on an \"AS IS\" BASIS,\n13:   ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n14:   ~ See the License for the specific language governing permissions and\n15:   ~ limitations under the License.\n16:   -->\n17: <project xmlns=\"http://maven.apache.org/POM/4.0.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd\">\n18:     <modelVersion>4.0.0</modelVersion>\n19: \n20:     <parent>\n21:         <groupId>com.okta</groupId>\n22:         <artifactId>okta-parent</artifactId>\n23:         <version>38</version>\n24:     </parent>\n25: \n26:     <groupId>com.okta.sdk</groupId>\n27:     <artifactId>okta-sdk-root</artifa",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C005",
      "file": "impl/pom.xml",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: <?xml version=\"1.0\" encoding=\"UTF-8\"?>\n2: <!--\n3:   ~ Copyright 2017 Okta\n4:   ~\n5:   ~ Licensed under the Apache License, Version 2.0 (the \"License\");\n6:   ~ you may not use this file except in compliance with the License.\n7:   ~ You may obtain a copy of the License at\n8:   ~\n9:   ~     http://www.apache.org/licenses/LICENSE-2.0\n10:   ~\n11:   ~ Unless required by applicable law or agreed to in writing, software\n12:   ~ distributed under the License is distributed on an \"AS IS\" BASIS,\n13:   ~ WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n14:   ~ See the License for the specific language governing permissions and\n15:   ~ limitations under the License.\n16:   -->\n17: <project xmlns=\"http://maven.apache.org/POM/4.0.0\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd\">\n18: \n19:     <modelVersion>4.0.0</modelVersion>\n20: \n21:     <parent>\n22:         <groupId>com.okta.sdk</groupId>\n23:         <artifactId>okta-sdk-root</artifactId>\n24:         <version>24.0.1-SNAPSHOT</version>\n25:     </parent>\n26: \n27:     <artifactId>okta-sdk-impl</artifactId>\n28:     <name",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C006",
      "file": "impl/pom.xml",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41:         </dependency>\n42:         <dependency>\n43:             <groupId>org.slf4j</groupId>\n44:             <artifactId>slf4j-api</artifactId>\n45:         </dependency>\n46:         <!-- HTTP client: apache client -->\n47:         <dependency>\n48:             <groupId>org.apache.httpcomponents.client5</groupId>\n49:             <artifactId>httpclient5</artifactId>\n50:         </dependency>\n51:         <dependency>\n52:             <groupId>com.okta.commons</groupId>\n53:             <artifactId>okta-config-check</artifactId>\n54:         </dependency>\n55:         <dependency>\n56:             <groupId>com.fasterxml.jackson.core</groupId>\n57:             <artifactId>jackson-databind</artifactId>\n58:         </dependency>\n59:         <dependency>\n60:             <groupId>org.yaml</groupId>\n61:             <artifactId>snakeyaml</artifactId>\n62:         </dependency>\n63:         <dependency>\n64:             <groupId>org.bouncycastle</groupId>\n65:             <artifactId>bcprov-jdk18on</artifactId>\n66:         </dependency>\n67:         <dependency>\n68:             <groupId>org.bouncycastle</groupId>\n69:             <artifactId>bcpkix-jdk18on</artifactId>\n70:         </dependency>\n71:      ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C007",
      "file": "impl/src/main/java/com/okta/sdk/impl/client/DefaultClientBuilder.java",
      "lines": {
        "end": 640,
        "start": 561
      },
      "snippet": "561:         Assert.notNull(path, \"The path to the privateKey cannot be null.\");\n562:         return getFileContent(path.toFile());\n563:     }\n564: \n565:     private String getFileContent(InputStream privateKeyStream) {\n566:         try {\n567:             return readFromInputStream(privateKeyStream);\n568:         } catch (IOException e) {\n569:             throw new IllegalArgumentException(\"Could not read from supplied privateKey input stream\");\n570:         }\n571:     }\n572: \n573:     private String readFromInputStream(InputStream inputStream) throws IOException {\n574:         Assert.notNull(inputStream, \"InputStream cannot be null.\");\n575:         StringBuilder resultStringBuilder = new StringBuilder();\n576:         try (BufferedReader br = new BufferedReader(new InputStreamReader(\n577:             inputStream, StandardCharsets.UTF_8))) {\n578:             String line;\n579:             while ((line = br.readLine()) != null) {\n580:                 resultStringBuilder.append(line).append(\"\\n\");\n581:             }\n582:         }\n583:         return resultStringBuilder.toString();\n584:     }\n585: \n586:     @Override\n587:     public ClientBuilder setCustomJwtSigner(UnaryOperator<byte[]",
      "span_kind": "sliding_window",
      "symbol": "getFileContent"
    },
    {
      "candidate_id": "C008",
      "file": "impl/src/main/java/com/okta/sdk/impl/client/DefaultClientBuilder.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2014 Stormpath, Inc.\n3:  * Modifications Copyright 2018 Okta, Inc.\n4:  *\n5:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n6:  * you may not use this file except in compliance with the License.\n7:  * You may obtain a copy of the License at\n8:  *\n9:  *     http://www.apache.org/licenses/LICENSE-2.0\n10:  *\n11:  * Unless required by applicable law or agreed to in writing, software\n12:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n13:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n14:  * See the License for the specific language governing permissions and\n15:  * limitations under the License.\n16:  */\n17: package com.okta.sdk.impl.client;\n18: \n19: import com.fasterxml.jackson.databind.ObjectMapper;\n20: import com.fasterxml.jackson.databind.module.SimpleModule;\n21: import com.okta.commons.configcheck.ConfigurationValidator;\n22: import com.okta.commons.http.config.Proxy;\n23: import com.okta.commons.lang.ApplicationInfo;\n24: import com.okta.commons.lang.Assert;\n25: import com.okta.commons.lang.Classes;\n26: import com.okta.commons.lang.Strings;\n27: import com.okta.sdk.authc.credentials.ClientCredent",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C009",
      "file": "impl/src/main/java/com/okta/sdk/impl/oauth2/AccessTokenRetrieverServiceImpl.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import org.slf4j.Logger;\n42: import org.slf4j.LoggerFactory;\n43: \n44: import java.io.ByteArrayOutputStream;\n45: import java.io.IOException;\n46: import java.io.InputStream;\n47: import java.io.Reader;\n48: import java.io.StringReader;\n49: import java.nio.charset.Charset;\n50: import java.nio.file.Files;\n51: import java.nio.file.Paths;\n52: import java.security.InvalidKeyException;\n53: import java.security.Key;\n54: import java.security.KeyPair;\n55: import java.security.PrivateKey;\n56: import java.time.Instant;\n57: import java.time.temporal.ChronoUnit;\n58: import java.util.*;\n59: \n60: /**\n61:  * Implementation of {@link AccessTokenRetrieverService} interface.\n62:  * This has logic to fetch OAuth2 access token from the Authorization server endpoint.\n63:  * @since 1.6.0\n64:  */\n65: public class AccessTokenRetrieverServiceImpl implements AccessTokenRetrieverService {\n66:     private static final Logger log = LoggerFactory.getLogger(AccessTokenRetrieverServiceImpl.class);\n67: \n68:     static final String TOKEN_URI  = \"/oauth2/v1/token\";\n69: \n70:     private static final KeyPair DUMMY_KEY_PAIR = Jwts.SIG.RS256.keyPair().build();\n71: \n72:     /**\n73:      * Custom SecureDigestAlgorithm that",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C010",
      "file": "impl/src/main/java/com/okta/sdk/impl/oauth2/DPoPInterceptor.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2024-Present Okta, Inc.\n3:  *\n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  *\n8:  *     http://www.apache.org/licenses/LICENSE-2.0\n9:  *\n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: package com.okta.sdk.impl.oauth2;\n17: \n18: import com.fasterxml.jackson.databind.JsonNode;\n19: import com.fasterxml.jackson.databind.ObjectMapper;\n20: import io.jsonwebtoken.JwtBuilder;\n21: import io.jsonwebtoken.Jwts;\n22: import io.jsonwebtoken.io.Encoders;\n23: import io.jsonwebtoken.security.Jwks;\n24: import io.jsonwebtoken.security.PrivateJwk;\n25: import org.apache.commons.lang3.StringUtils;\n26: import org.apache.hc.client5.http.classic.ExecChain;\n27: import org.apache.hc.client5.http.classic.ExecChainHandler;\n28: import org.apache.hc",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: concurrent_object_lifecycle\nGuideline: Trace mutable files, paths, objects, identities, request fields, or shared state that are checked before use into sensitive file, state, permission, memory, or resource effects that depend on the earlier check. Report code paths where the checked value is not stabilized with a handle, lock, transaction, immutable copy, or atomic operation before the effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should bind the check to a stable reference or perform the check and effect under the same atomic operation or synchronization boundary.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 1
  }
}

Return JSON only. Do not call tools or run commands.