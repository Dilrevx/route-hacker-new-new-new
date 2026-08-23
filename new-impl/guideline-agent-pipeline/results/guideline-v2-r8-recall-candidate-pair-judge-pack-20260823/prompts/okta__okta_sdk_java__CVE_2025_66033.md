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
      "file": "api/src/main/java/com/okta/sdk/helper/PaginationUtil.java",
      "label": "A",
      "lines": {
        "end": 128,
        "start": 81
      },
      "snippet": "81:      */\n82:     private static String getNextPage(ApiClient apiClient) {\n83: \n84:         Assert.notNull(apiClient, \"apiClient cannot be null\");\n85:         Assert.notNull(apiClient.getResponseHeaders(), \"apiClient is missing response headers\");\n86:         Assert.notNull(apiClient.getResponseHeaders().get(\"link\"), \"apiClient is missing 'link' response headers\");\n87: \n88:         List<String> linkHeaders = apiClient.getResponseHeaders().get(\"link\");\n89: \n90:         String nextPage = null;\n91: \n92:         for (String linkHeader : linkHeaders) {\n93:             String[] parts = linkHeader.split(\"; *\");\n94:             String url = parts[0]\n95:                 .replaceAll(\"<\", \"\")\n96:                 .replaceAll(\">\", \"\");\n97:             String rel = parts[1];\n98:             if (rel.equals(\"rel=\\\"next\\\"\")) {\n99:                 nextPage = url;\n100:             }\n101:         }\n102: \n103:         log.debug(\"Next Page: {}\", nextPage);\n104:         return nextPage;\n105:     }\n106: \n107:     /**\n108:      * Split a URL with query strings into name value pairs.\n109:      *\n110:      * @param url the url to split\n111:      * @return map of query string name value pairs\n112:      * @throws UnsupportedEncodingException If character encoding needs to be consulted\n113:      */\n114:     private static Map<String, String> splitQuery(URL url) throws UnsupportedEncodingException {\n115: \n116:         Assert.notNull(url, \"url cannot be null\");\n117: \n118:         Map<String, String> query_pairs = new LinkedHashMap<>();\n119:         String query = url.getQuery();\n120:         String[] pairs = query.split(\"&\");\n121:         for (String pair : pairs) {\n122:             int index = pair.indexOf(\"=\");\n123:             query_pairs.put(URLDecoder.decode(pair.substring(0, index), StandardCharsets.UTF_8.name()),\n124:                 URLDecoder.decode(pair.substring(index + 1), StandardCharsets.UTF_8.name()));\n125:         }\n126:         return query_pairs;\n127:     }\n128: }",
      "span_kind": "sliding_window",
      "symbol": "URL"
    },
    {
      "file": "pom.xml",
      "label": "B",
      "lines": {
        "end": 200,
        "start": 121
      },
      "snippet": "121:             </dependency>\n122:             <dependency>\n123:                 <groupId>org.slf4j</groupId>\n124:                 <artifactId>jcl-over-slf4j</artifactId>\n125:                 <version>${slf4j.version}</version>\n126:             </dependency>\n127:             <dependency>\n128:                 <groupId>ch.qos.logback</groupId>\n129:                 <artifactId>logback-classic</artifactId>\n130:                 <version>1.3.14</version>\n131:             </dependency>\n132: \n133:             <!-- Bouncy Castle -->\n134:             <dependency>\n135:                 <groupId>org.bouncycastle</groupId>\n136:                 <artifactId>bcprov-jdk18on</artifactId>\n137:                 <version>${bouncycastle.version}</version>\n138:             </dependency>\n139: \n140:             <dependency>\n141:                 <groupId>org.bouncycastle</groupId>\n142:                 <artifactId>bcpkix-jdk18on</artifactId>\n143:                 <version>${bouncycastle.version}</version>\n144:             </dependency>\n145: \n146:             <!-- JJWT -->\n147:             <dependency>\n148:                 <groupId>io.jsonwebtoken</groupId>\n149:                 <artifactId>jjwt-api</artifactId>\n150:                 <version>${jjwt.version}</version>\n151:             </dependency>\n152:             <dependency>\n153:                 <groupId>io.jsonwebtoken</groupId>\n154:                 <artifactId>jjwt-impl</artifactId>\n155:                 <version>${jjwt.version}</version>\n156:                 <scope>runtime</scope>\n157:             </dependency>\n158:             <dependency>\n159:                 <groupId>io.jsonwebtoken</groupId>\n160:                 <artifactId>jjwt-jackson</artifactId>\n161:                 <version>${jjwt.version}</version>\n162:                 <scope>runtime</scope>\n163:             </dependency>\n164: \n165:             <dependency>\n166:                 <groupId>org.apache.httpcomponents.client5</groupId>\n167:                 <artifactId>httpclient5</artifactId>\n168:                 <version>${org.apache.httpcomponents.client5.version}</version>\n169:             </dependency>\n170: \n171:             <dependency>\n172:                 <groupId>org.yaml</groupId>\n173:                 <artifactId>snakeyaml</artifactId>\n174:                 <version>${snakeyaml.version}</version>\n175:             </dependency>\n176:             <dependency>\n177:                 <groupId>com.google.auto.service</groupId>\n178:                 <artifactId>auto-service</artifactId>\n179:                 <version>${com.google.auto.service.version}</version>\n180:                 <optional>true</optional>\n181:             </dependency>\n182:             <dependency>\n183:                 <groupId>com.google.guava</groupId>\n184:                 <artifactId>guava</artifactId>\n185:                 <version>32.0.1-jre</version>\n186:                 <scope>test</scope>\n187:             </dependency>\n188:             <dependency>\n189:                 <groupId>org.testng</groupId>\n190:                 <artifactId>testng</artifactId>\n191:                 <version>7.0.0</version>\n192:                 <scope>test</scope>\n193:                 <exclusions>\n194:                     <exclusion>\n195:                         <groupId>org.beanshell</groupId>\n196:                         <artifactId>bsh</artifactId>\n197:                     </exclusion>\n198:                 </exclusions>\n199:             </dependency>\n200:             <dependency>",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: concurrent_object_lifecycle\nGuideline: Trace mutable files, paths, objects, identities, request fields, or shared state that are checked before use into sensitive file, state, permission, memory, or resource effects that depend on the earlier check. Report code paths where the checked value is not stabilized with a handle, lock, transaction, immutable copy, or atomic operation before the effect. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 2 historical CVE example(s), not as a project-specific signature. A safe implementation should bind the check to a stable reference or perform the check and effect under the same atomic operation or synchronization boundary.",
  "judge_mode": "recall_candidate_pair_advisory"
}

Return JSON only. Do not call tools or run commands.