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
      "file": "samples/client/petstore/java/okhttp-gson/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 880,
        "start": 801
      },
      "snippet": "801:             int pos = filename.lastIndexOf(\".\");\n802:             if (pos == -1) {\n803:                 prefix = filename + \"-\";\n804:             } else {\n805:                 prefix = filename.substring(0, pos) + \"-\";\n806:                 suffix = filename.substring(pos);\n807:             }\n808:             // File.createTempFile requires the prefix to be at least three characters long\n809:             if (prefix.length() < 3)\n810:                 prefix = \"download-\";\n811:         }\n812: \n813:         if (tempFolderPath == null)\n814:             return File.createTempFile(prefix, suffix);\n815:         else\n816:             return File.createTempFile(prefix, suffix, new File(tempFolderPath));\n817:     }\n818: \n819:     /**\n820:      * {@link #execute(Call, Type)}\n821:      *\n822:      * @param <T> Type\n823:      * @param call An instance of the Call object\n824:      * @throws ApiException If fail to execute the call\n825:      * @return ApiResponse&lt;T&gt;\n826:      */\n827:     public <T> ApiResponse<T> execute(Call call) throws ApiException {\n828:         return execute(call, null);\n829:     }\n830: \n831:     /**\n832:      * Execute HTTP call and deserialize the HTTP response ",
      "span_kind": "sliding_window",
      "symbol": "prepareDownloadFile"
    },
    {
      "candidate_id": "C012",
      "file": "samples/client/petstore/java/jersey2-java6/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 680,
        "start": 601
      },
      "snippet": "601:     String prefix;\n602:     String suffix = null;\n603:     if (filename == null) {\n604:       prefix = \"download-\";\n605:       suffix = \"\";\n606:     } else {\n607:       int pos = filename.lastIndexOf('.');\n608:       if (pos == -1) {\n609:         prefix = filename + \"-\";\n610:       } else {\n611:         prefix = filename.substring(0, pos) + \"-\";\n612:         suffix = filename.substring(pos);\n613:       }\n614:       // File.createTempFile requires the prefix to be at least three characters long\n615:       if (prefix.length() < 3)\n616:         prefix = \"download-\";\n617:     }\n618: \n619:     if (tempFolderPath == null)\n620:       return File.createTempFile(prefix, suffix);\n621:     else\n622:       return File.createTempFile(prefix, suffix, new File(tempFolderPath));\n623:   }\n624: \n625:   /**\n626:    * Invoke API by sending HTTP request with the given options.\n627:    *\n628:    * @param <T> Type\n629:    * @param path The sub-path of the HTTP URL\n630:    * @param method The request method, one of \"GET\", \"POST\", \"PUT\", \"HEAD\" and \"DELETE\"\n631:    * @param queryParams The query parameters\n632:    * @param body The request body object\n633:    * @param headerParams The header parameter",
      "span_kind": "sliding_window",
      "symbol": "prepareDownloadFile"
    },
    {
      "candidate_id": "C013",
      "file": "samples/server/petstore/java-vertx/async/src/main/resources/vertx-default-jul-logging.properties",
      "lines": {
        "end": 30,
        "start": 1
      },
      "snippet": "1: #\n2: # Copyright 2014 Red Hat, Inc.\n3: #\n4: #  All rights reserved. This program and the accompanying materials\n5: #  are made available under the terms of the Eclipse Public License v1.0\n6: #  and Apache License v2.0 which accompanies this distribution.\n7: #\n8: #  The Eclipse Public License is available at\n9: #  http://www.eclipse.org/legal/epl-v10.html\n10: #\n11: #  The Apache License v2.0 is available at\n12: #  http://www.opensource.org/licenses/apache2.0.php\n13: #\n14: #  You may elect to redistribute this code under either of these licenses.\n15: #\n16: handlers=java.util.logging.ConsoleHandler,java.util.logging.FileHandler\n17: java.util.logging.SimpleFormatter.format=%5$s %6$s\\n\n18: java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter\n19: java.util.logging.ConsoleHandler.level=FINEST\n20: java.util.logging.FileHandler.level=INFO\n21: java.util.logging.FileHandler.formatter=io.vertx.core.logging.VertxLoggerFormatter\n22: \n23: # Put the log in the system temporary directory\n24: java.util.logging.FileHandler.pattern=vertx.log\n25: \n26: .level=INFO\n27: io.vertx.ext.web.level=FINEST\n28: io.vertx.level=INFO\n29: com.hazelcast.level=INFO\n30: io.netty.util.internal.",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C014",
      "file": "modules/swagger-codegen/src/main/java/io/swagger/codegen/AbstractGenerator.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package io.swagger.codegen;\n2: \n3: import java.io.BufferedWriter;\n4: import java.io.File;\n5: import java.io.FileInputStream;\n6: import java.io.FileOutputStream;\n7: import java.io.IOException;\n8: import java.io.InputStream;\n9: import java.io.InputStreamReader;\n10: import java.io.OutputStreamWriter;\n11: import java.io.Reader;\n12: import java.io.Writer;\n13: import java.util.Scanner;\n14: import java.util.regex.Pattern;\n15: \n16: import org.apache.commons.lang3.StringUtils;\n17: import org.slf4j.Logger;\n18: import org.slf4j.LoggerFactory;\n19: \n20: public abstract class AbstractGenerator {\n21:     private static final Logger LOGGER = LoggerFactory.getLogger(AbstractGenerator.class);\n22: \n23:     @SuppressWarnings(\"static-method\")\n24:     public File writeToFile(String filename, String contents) throws IOException {\n25:         LOGGER.info(\"writing file \" + filename);\n26:         File output = new File(filename);\n27: \n28:         if (output.getParent() != null && !new File(output.getParent()).exists()) {\n29:             File parent = new File(output.getParent());\n30:             parent.mkdirs();\n31:         }\n32:         Writer out = new BufferedWriter(new OutputStreamWriter(\n33:        ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C015",
      "file": "modules/swagger-codegen/src/main/java/io/swagger/codegen/languages/Apache2ConfigCodegen.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package io.swagger.codegen.languages;\n2: \n3: import java.util.ArrayList;\n4: import java.util.Arrays;\n5: import java.util.HashMap;\n6: import java.util.HashSet;\n7: import java.util.List;\n8: import java.util.Map;\n9: \n10: import io.swagger.codegen.CliOption;\n11: import io.swagger.codegen.CodegenConfig;\n12: import io.swagger.codegen.CodegenConstants;\n13: import io.swagger.codegen.CodegenOperation;\n14: import io.swagger.codegen.CodegenType;\n15: import io.swagger.codegen.DefaultCodegen;\n16: import io.swagger.codegen.SupportingFile;\n17: \n18: public class Apache2ConfigCodegen extends DefaultCodegen implements CodegenConfig {\n19:   public static final String USER_INFO_PATH = \"userInfoPath\";\n20:   protected String userInfoPath = \"/var/www/html/\";\n21: \n22:   @Override\n23:   public CodegenType getTag() {\n24:     return CodegenType.CONFIG;\n25:   }\n26: \n27:   @Override\n28:   public String getName() {\n29:     return \"apache2\";\n30:   }\n31: \n32:   @Override\n33:   public String getHelp() {\n34:     return \"Generates an Apache2 Config file with the permissions\";\n35:   }\n36: \n37:   public Apache2ConfigCodegen() {\n38:     super();\n39:     apiTemplateFiles.put(\"apache-config.mustache\", \".conf\");\n40: \n4",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C016",
      "file": "samples/client/petstore/java/okhttp-gson/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 480,
        "start": 401
      },
      "snippet": "401:      * the system's default tempopary folder.\n402:      *\n403:      * @see <a href=\"https://docs.oracle.com/javase/7/docs/api/java/io/File.html#createTempFile\">createTempFile</a>\n404:      * @return Temporary folder path\n405:      */\n406:     public String getTempFolderPath() {\n407:         return tempFolderPath;\n408:     }\n409: \n410:     /**\n411:      * Set the temporary folder path (for downloading files)\n412:      *\n413:      * @param tempFolderPath Temporary folder path\n414:      * @return ApiClient\n415:      */\n416:     public ApiClient setTempFolderPath(String tempFolderPath) {\n417:         this.tempFolderPath = tempFolderPath;\n418:         return this;\n419:     }\n420: \n421:     /**\n422:      * Get connection timeout (in milliseconds).\n423:      *\n424:      * @return Timeout in milliseconds\n425:      */\n426:     public int getConnectTimeout() {\n427:         return httpClient.getConnectTimeout();\n428:     }\n429: \n430:     /**\n431:      * Sets the connect timeout (in milliseconds).\n432:      * A value of 0 means no timeout, otherwise values must be between 1 and\n433:      * {@link Integer#MAX_VALUE}.\n434:      *\n435:      * @param connectionTimeout connection timeout in mi",
      "span_kind": "sliding_window",
      "symbol": "setDebugging"
    },
    {
      "candidate_id": "C017",
      "file": "samples/client/petstore/java/jersey2/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 680,
        "start": 601
      },
      "snippet": "601:     String prefix;\n602:     String suffix = null;\n603:     if (filename == null) {\n604:       prefix = \"download-\";\n605:       suffix = \"\";\n606:     } else {\n607:       int pos = filename.lastIndexOf('.');\n608:       if (pos == -1) {\n609:         prefix = filename + \"-\";\n610:       } else {\n611:         prefix = filename.substring(0, pos) + \"-\";\n612:         suffix = filename.substring(pos);\n613:       }\n614:       // File.createTempFile requires the prefix to be at least three characters long\n615:       if (prefix.length() < 3)\n616:         prefix = \"download-\";\n617:     }\n618: \n619:     if (tempFolderPath == null)\n620:       return File.createTempFile(prefix, suffix);\n621:     else\n622:       return File.createTempFile(prefix, suffix, new File(tempFolderPath));\n623:   }\n624: \n625:   /**\n626:    * Invoke API by sending HTTP request with the given options.\n627:    *\n628:    * @param <T> Type\n629:    * @param path The sub-path of the HTTP URL\n630:    * @param method The request method, one of \"GET\", \"POST\", \"PUT\", \"HEAD\" and \"DELETE\"\n631:    * @param queryParams The query parameters\n632:    * @param body The request body object\n633:    * @param headerParams The header parameter",
      "span_kind": "sliding_window",
      "symbol": "prepareDownloadFile"
    },
    {
      "candidate_id": "C018",
      "file": "samples/client/petstore-security-test/java/okhttp-gson/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 480,
        "start": 401
      },
      "snippet": "401:      * @see <a href=\"https://docs.oracle.com/javase/7/docs/api/java/io/File.html#createTempFile\">createTempFile</a>\n402:      * @return Temporary folder path\n403:      */\n404:     public String getTempFolderPath() {\n405:         return tempFolderPath;\n406:     }\n407: \n408:     /**\n409:      * Set the temporary folder path (for downloading files)\n410:      *\n411:      * @param tempFolderPath Temporary folder path\n412:      * @return ApiClient\n413:      */\n414:     public ApiClient setTempFolderPath(String tempFolderPath) {\n415:         this.tempFolderPath = tempFolderPath;\n416:         return this;\n417:     }\n418: \n419:     /**\n420:      * Get connection timeout (in milliseconds).\n421:      *\n422:      * @return Timeout in milliseconds\n423:      */\n424:     public int getConnectTimeout() {\n425:         return httpClient.getConnectTimeout();\n426:     }\n427: \n428:     /**\n429:      * Sets the connect timeout (in milliseconds).\n430:      * A value of 0 means no timeout, otherwise values must be between 1 and\n431:      * {@link Integer#MAX_VALUE}.\n432:      *\n433:      * @param connectionTimeout connection timeout in milliseconds\n434:      * @return Api client\n435:      */\n436:    ",
      "span_kind": "sliding_window",
      "symbol": "setDebugging"
    },
    {
      "candidate_id": "C019",
      "file": "samples/client/petstore-security-test/java/okhttp-gson/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 880,
        "start": 801
      },
      "snippet": "801:                 prefix = filename + \"-\";\n802:             } else {\n803:                 prefix = filename.substring(0, pos) + \"-\";\n804:                 suffix = filename.substring(pos);\n805:             }\n806:             // File.createTempFile requires the prefix to be at least three characters long\n807:             if (prefix.length() < 3)\n808:                 prefix = \"download-\";\n809:         }\n810: \n811:         if (tempFolderPath == null)\n812:             return File.createTempFile(prefix, suffix);\n813:         else\n814:             return File.createTempFile(prefix, suffix, new File(tempFolderPath));\n815:     }\n816: \n817:     /**\n818:      * {@link #execute(Call, Type)}\n819:      *\n820:      * @param <T> Type\n821:      * @param call An instance of the Call object\n822:      * @throws ApiException If fail to execute the call\n823:      * @return ApiResponse&lt;T&gt;\n824:      */\n825:     public <T> ApiResponse<T> execute(Call call) throws ApiException {\n826:         return execute(call, null);\n827:     }\n828: \n829:     /**\n830:      * Execute HTTP call and deserialize the HTTP response body into the given return type.\n831:      *\n832:      * @param returnType The return ty",
      "span_kind": "sliding_window",
      "symbol": "prepareDownloadFile"
    },
    {
      "candidate_id": "C020",
      "file": "samples/server/petstore/java-vertx/rx/src/main/resources/vertx-default-jul-logging.properties",
      "lines": {
        "end": 30,
        "start": 1
      },
      "snippet": "1: #\n2: # Copyright 2014 Red Hat, Inc.\n3: #\n4: #  All rights reserved. This program and the accompanying materials\n5: #  are made available under the terms of the Eclipse Public License v1.0\n6: #  and Apache License v2.0 which accompanies this distribution.\n7: #\n8: #  The Eclipse Public License is available at\n9: #  http://www.eclipse.org/legal/epl-v10.html\n10: #\n11: #  The Apache License v2.0 is available at\n12: #  http://www.opensource.org/licenses/apache2.0.php\n13: #\n14: #  You may elect to redistribute this code under either of these licenses.\n15: #\n16: handlers=java.util.logging.ConsoleHandler,java.util.logging.FileHandler\n17: java.util.logging.SimpleFormatter.format=%5$s %6$s\\n\n18: java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter\n19: java.util.logging.ConsoleHandler.level=FINEST\n20: java.util.logging.FileHandler.level=INFO\n21: java.util.logging.FileHandler.formatter=io.vertx.core.logging.VertxLoggerFormatter\n22: \n23: # Put the log in the system temporary directory\n24: java.util.logging.FileHandler.pattern=vertx.log\n25: \n26: .level=INFO\n27: io.vertx.ext.web.level=FINEST\n28: io.vertx.level=INFO\n29: com.hazelcast.level=INFO\n30: io.netty.util.internal.",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: toctou_check_use_race\nGuideline: Trace temporary file or directory names created in shared writable locations into manual temporary directory creation sequences such as createTempFile, delete, then mkdir or mkdirs. Report code paths where the temporary path is released between creation and directory creation, allowing another actor to replace or pre-create it before use. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 10 historical CVE example(s), not as a project-specific signature. A safe implementation should use an atomic temporary-directory API such as Files.createTempDirectory and avoid delete-then-mkdir sequences.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 2
  }
}

Return JSON only. Do not call tools or run commands.