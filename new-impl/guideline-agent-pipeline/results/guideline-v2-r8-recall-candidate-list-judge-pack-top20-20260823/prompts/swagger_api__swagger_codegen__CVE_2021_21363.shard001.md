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
      "file": "samples/client/petstore/java/jersey2/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 320,
        "start": 241
      },
      "snippet": "241:     this.httpClient = buildHttpClient(debugging);\n242:     return this;\n243:   }\n244: \n245:   /**\n246:    * The path of temporary folder used to store downloaded files from endpoints\n247:    * with file response. The default value is <code>null</code>, i.e. using\n248:    * the system's default tempopary folder.\n249:    *\n250:    * @return Temp folder path\n251:    */\n252:   public String getTempFolderPath() {\n253:     return tempFolderPath;\n254:   }\n255: \n256:   /**\n257:    * Set temp folder path\n258:    * @param tempFolderPath Temp folder path\n259:    * @return API client\n260:    */\n261:   public ApiClient setTempFolderPath(String tempFolderPath) {\n262:     this.tempFolderPath = tempFolderPath;\n263:     return this;\n264:   }\n265: \n266:   /**\n267:    * Connect timeout (in milliseconds).\n268:    * @return Connection timeout\n269:    */\n270:   public int getConnectTimeout() {\n271:     return connectionTimeout;\n272:   }\n273: \n274:   /**\n275:    * Set the connect timeout (in milliseconds).\n276:    * A value of 0 means no timeout, otherwise values must be between 1 and\n277:    * {@link Integer#MAX_VALUE}.\n278:    * @param connectionTimeout Connection timeout in milliseconds\n279:    *",
      "span_kind": "sliding_window",
      "symbol": "setDebugging"
    },
    {
      "candidate_id": "C002",
      "file": "samples/client/petstore/java/jersey2-java6/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 320,
        "start": 241
      },
      "snippet": "241:     return this;\n242:   }\n243: \n244:   /**\n245:    * The path of temporary folder used to store downloaded files from endpoints\n246:    * with file response. The default value is <code>null</code>, i.e. using\n247:    * the system's default tempopary folder.\n248:    *\n249:    * @return Temp folder path\n250:    */\n251:   public String getTempFolderPath() {\n252:     return tempFolderPath;\n253:   }\n254: \n255:   /**\n256:    * Set temp folder path\n257:    * @param tempFolderPath Temp folder path\n258:    * @return API client\n259:    */\n260:   public ApiClient setTempFolderPath(String tempFolderPath) {\n261:     this.tempFolderPath = tempFolderPath;\n262:     return this;\n263:   }\n264: \n265:   /**\n266:    * Connect timeout (in milliseconds).\n267:    * @return Connection timeout\n268:    */\n269:   public int getConnectTimeout() {\n270:     return connectionTimeout;\n271:   }\n272: \n273:   /**\n274:    * Set the connect timeout (in milliseconds).\n275:    * A value of 0 means no timeout, otherwise values must be between 1 and\n276:    * {@link Integer#MAX_VALUE}.\n277:    * @param connectionTimeout Connection timeout in milliseconds\n278:    * @return API client\n279:    */\n280:   public ApiClient ",
      "span_kind": "sliding_window",
      "symbol": "setDebugging"
    },
    {
      "candidate_id": "C003",
      "file": "modules/swagger-codegen/src/main/java/io/swagger/codegen/languages/JavaPKMSTServerCodegen.java",
      "lines": {
        "end": 320,
        "start": 241
      },
      "snippet": "241:         this.supportingFiles\n242:                 .add(new SupportingFile(\"security\" + File.separator + \"oAuth2SecurityConfiguration.mustache\",\n243:                         (this.sourceFolder + File.separator + this.basePackage).replace(\".\", File.separator)\n244:                                 + File.separator + \"security\",\n245:                         \"OAuth2SecurityConfiguration.java\"));\n246:         this.supportingFiles\n247:                 .add(new SupportingFile(\"security\" + File.separator + \"resourceServerConfiguration.mustache\",\n248:                         (this.sourceFolder + File.separator + this.basePackage).replace(\".\", File.separator)\n249:                                 + File.separator + \"security\",\n250:                         \"ResourceServerConfiguration.java\"));\n251: \n252:         // logging\n253: \n254:         this.supportingFiles.add(new SupportingFile(\"logging\" + File.separator + \"httpLoggingFilter.mustache\",\n255:                 (this.sourceFolder + File.separator + this.basePackage).replace(\".\", File.separator) + File.separator\n256:                         + \"logging\",\n257:                 \"HttpLoggingFilter.java\"));\n258: \n259:         // Resources\n260:  ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C004",
      "file": "modules/swagger-codegen/src/main/java/io/swagger/codegen/languages/JavaClientCodegen.java",
      "lines": {
        "end": 240,
        "start": 161
      },
      "snippet": "161:         final String invokerFolder = (sourceFolder + '/' + invokerPackage).replace(\".\", \"/\");\n162:         final String authFolder = (sourceFolder + '/' + invokerPackage + \".auth\").replace(\".\", \"/\");\n163:         final String apiFolder = (sourceFolder + '/' + apiPackage).replace(\".\", \"/\");\n164: \n165:         //Common files\n166:         writeOptional(outputFolder, new SupportingFile(\"pom.mustache\", \"\", \"pom.xml\"));\n167:         writeOptional(outputFolder, new SupportingFile(\"README.mustache\", \"\", \"README.md\"));\n168:         writeOptional(outputFolder, new SupportingFile(\"build.gradle.mustache\", \"\", \"build.gradle\"));\n169:         writeOptional(outputFolder, new SupportingFile(\"build.sbt.mustache\", \"\", \"build.sbt\"));\n170:         writeOptional(outputFolder, new SupportingFile(\"settings.gradle.mustache\", \"\", \"settings.gradle\"));\n171:         writeOptional(outputFolder, new SupportingFile(\"gradle.properties.mustache\", \"\", \"gradle.properties\"));\n172:         writeOptional(outputFolder, new SupportingFile(\"manifest.mustache\", projectFolder, \"AndroidManifest.xml\"));\n173:         supportingFiles.add(new SupportingFile(\"travis.mustache\", \"\", \".travis.yml\"));\n174:         supportingFiles",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C005",
      "file": "samples/client/petstore/java/jersey2-java8/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 680,
        "start": 601
      },
      "snippet": "601:     String prefix;\n602:     String suffix = null;\n603:     if (filename == null) {\n604:       prefix = \"download-\";\n605:       suffix = \"\";\n606:     } else {\n607:       int pos = filename.lastIndexOf('.');\n608:       if (pos == -1) {\n609:         prefix = filename + \"-\";\n610:       } else {\n611:         prefix = filename.substring(0, pos) + \"-\";\n612:         suffix = filename.substring(pos);\n613:       }\n614:       // File.createTempFile requires the prefix to be at least three characters long\n615:       if (prefix.length() < 3)\n616:         prefix = \"download-\";\n617:     }\n618: \n619:     if (tempFolderPath == null)\n620:       return File.createTempFile(prefix, suffix);\n621:     else\n622:       return File.createTempFile(prefix, suffix, new File(tempFolderPath));\n623:   }\n624: \n625:   /**\n626:    * Invoke API by sending HTTP request with the given options.\n627:    *\n628:    * @param <T> Type\n629:    * @param path The sub-path of the HTTP URL\n630:    * @param method The request method, one of \"GET\", \"POST\", \"PUT\", \"HEAD\" and \"DELETE\"\n631:    * @param queryParams The query parameters\n632:    * @param body The request body object\n633:    * @param headerParams The header parameter",
      "span_kind": "sliding_window",
      "symbol": "prepareDownloadFile"
    },
    {
      "candidate_id": "C006",
      "file": "samples/client/petstore/java/jersey2-java8/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 320,
        "start": 241
      },
      "snippet": "241:     this.httpClient = buildHttpClient(debugging);\n242:     return this;\n243:   }\n244: \n245:   /**\n246:    * The path of temporary folder used to store downloaded files from endpoints\n247:    * with file response. The default value is <code>null</code>, i.e. using\n248:    * the system's default tempopary folder.\n249:    *\n250:    * @return Temp folder path\n251:    */\n252:   public String getTempFolderPath() {\n253:     return tempFolderPath;\n254:   }\n255: \n256:   /**\n257:    * Set temp folder path\n258:    * @param tempFolderPath Temp folder path\n259:    * @return API client\n260:    */\n261:   public ApiClient setTempFolderPath(String tempFolderPath) {\n262:     this.tempFolderPath = tempFolderPath;\n263:     return this;\n264:   }\n265: \n266:   /**\n267:    * Connect timeout (in milliseconds).\n268:    * @return Connection timeout\n269:    */\n270:   public int getConnectTimeout() {\n271:     return connectionTimeout;\n272:   }\n273: \n274:   /**\n275:    * Set the connect timeout (in milliseconds).\n276:    * A value of 0 means no timeout, otherwise values must be between 1 and\n277:    * {@link Integer#MAX_VALUE}.\n278:    * @param connectionTimeout Connection timeout in milliseconds\n279:    *",
      "span_kind": "sliding_window",
      "symbol": "setDebugging"
    },
    {
      "candidate_id": "C007",
      "file": "samples/client/petstore/java/okhttp-gson-parcelableModel/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 880,
        "start": 801
      },
      "snippet": "801:             int pos = filename.lastIndexOf(\".\");\n802:             if (pos == -1) {\n803:                 prefix = filename + \"-\";\n804:             } else {\n805:                 prefix = filename.substring(0, pos) + \"-\";\n806:                 suffix = filename.substring(pos);\n807:             }\n808:             // File.createTempFile requires the prefix to be at least three characters long\n809:             if (prefix.length() < 3)\n810:                 prefix = \"download-\";\n811:         }\n812: \n813:         if (tempFolderPath == null)\n814:             return File.createTempFile(prefix, suffix);\n815:         else\n816:             return File.createTempFile(prefix, suffix, new File(tempFolderPath));\n817:     }\n818: \n819:     /**\n820:      * {@link #execute(Call, Type)}\n821:      *\n822:      * @param <T> Type\n823:      * @param call An instance of the Call object\n824:      * @throws ApiException If fail to execute the call\n825:      * @return ApiResponse&lt;T&gt;\n826:      */\n827:     public <T> ApiResponse<T> execute(Call call) throws ApiException {\n828:         return execute(call, null);\n829:     }\n830: \n831:     /**\n832:      * Execute HTTP call and deserialize the HTTP response ",
      "span_kind": "sliding_window",
      "symbol": "prepareDownloadFile"
    },
    {
      "candidate_id": "C008",
      "file": "samples/client/petstore/java/okhttp-gson-parcelableModel/src/main/java/io/swagger/client/ApiClient.java",
      "lines": {
        "end": 480,
        "start": 401
      },
      "snippet": "401:      * the system's default tempopary folder.\n402:      *\n403:      * @see <a href=\"https://docs.oracle.com/javase/7/docs/api/java/io/File.html#createTempFile\">createTempFile</a>\n404:      * @return Temporary folder path\n405:      */\n406:     public String getTempFolderPath() {\n407:         return tempFolderPath;\n408:     }\n409: \n410:     /**\n411:      * Set the temporary folder path (for downloading files)\n412:      *\n413:      * @param tempFolderPath Temporary folder path\n414:      * @return ApiClient\n415:      */\n416:     public ApiClient setTempFolderPath(String tempFolderPath) {\n417:         this.tempFolderPath = tempFolderPath;\n418:         return this;\n419:     }\n420: \n421:     /**\n422:      * Get connection timeout (in milliseconds).\n423:      *\n424:      * @return Timeout in milliseconds\n425:      */\n426:     public int getConnectTimeout() {\n427:         return httpClient.getConnectTimeout();\n428:     }\n429: \n430:     /**\n431:      * Sets the connect timeout (in milliseconds).\n432:      * A value of 0 means no timeout, otherwise values must be between 1 and\n433:      * {@link Integer#MAX_VALUE}.\n434:      *\n435:      * @param connectionTimeout connection timeout in mi",
      "span_kind": "sliding_window",
      "symbol": "setDebugging"
    },
    {
      "candidate_id": "C009",
      "file": "modules/swagger-generator/src/main/java/io/swagger/generator/util/ZipUtil.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41:      * Compresses a collection of files to a destination zip file.\n42:      * \n43:      * @param listFiles A collection of files and directories\n44:      * @param destZipFile The path of the destination zip file\n45:      * @throws FileNotFoundException if file not found\n46:      * @throws IOException if IO exception occurs\n47:      */\n48:     public void compressFiles(List<File> listFiles, String destZipFile)\n49:             throws FileNotFoundException, IOException {\n50: \n51:         ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(destZipFile));\n52: \n53:         for (File file : listFiles) {\n54:             if (file.isDirectory()) {\n55:                 addFolderToZip(file, file.getName(), zos);\n56:             } else {\n57:                 addFileToZip(file, zos);\n58:             }\n59:         }\n60: \n61:         zos.flush();\n62:         zos.close();\n63:     }\n64: \n65:     /**\n66:      * Adds a directory to the current zip output stream.\n67:      * \n68:      * @param folder the directory to be added\n69:      * @param parentFolder the path of parent directory\n70:      * @param zos the current zip output stream\n71:      * @throws FileNotFoundException if file not fo",
      "span_kind": "sliding_window",
      "symbol": "ZipUtil"
    },
    {
      "candidate_id": "C010",
      "file": "modules/swagger-codegen/src/main/java/io/swagger/codegen/languages/JavaMSF4JServerCodegen.java",
      "lines": {
        "end": 152,
        "start": 81
      },
      "snippet": "81:             supportingFiles.add(new SupportingFile(\"JodaDateTimeProvider.mustache\", (sourceFolder + '/' + apiPackage).replace(\".\", \"/\"), \"JodaDateTimeProvider.java\"));\n82:             supportingFiles.add(new SupportingFile(\"JodaLocalDateProvider.mustache\", (sourceFolder + '/' + apiPackage).replace(\".\", \"/\"), \"JodaLocalDateProvider.java\"));\n83:         } else if ( dateLibrary.startsWith(\"java8\") ) {\n84:             supportingFiles.add(new SupportingFile(\"OffsetDateTimeProvider.mustache\", (sourceFolder + '/' + apiPackage).replace(\".\", \"/\"), \"OffsetDateTimeProvider.java\"));\n85:             supportingFiles.add(new SupportingFile(\"LocalDateProvider.mustache\", (sourceFolder + '/' + apiPackage).replace(\".\", \"/\"), \"LocalDateProvider.java\"));\n86:         }\n87: \n88:         writeOptional(outputFolder, new SupportingFile(\"pom.mustache\", \"\", \"pom.xml\"));\n89:         writeOptional(outputFolder, new SupportingFile(\"README.mustache\", \"\", \"README.md\"));\n90:         supportingFiles.add(new SupportingFile(\"ApiException.mustache\", (sourceFolder + '/' + apiPackage).replace(\".\", \"/\"), \"ApiException.java\"));\n91:         supportingFiles.add(new SupportingFile(\"ApiOriginFilter.mustache\", (sourceFolder",
      "span_kind": "sliding_window",
      "symbol": "processOpts"
    }
  ],
  "guideline": "HCVR type: toctou_check_use_race\nGuideline: Trace temporary file or directory names created in shared writable locations into manual temporary directory creation sequences such as createTempFile, delete, then mkdir or mkdirs. Report code paths where the temporary path is released between creation and directory creation, allowing another actor to replace or pre-create it before use. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 10 historical CVE example(s), not as a project-specific signature. A safe implementation should use an atomic temporary-directory API such as Files.createTempDirectory and avoid delete-then-mkdir sequences.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 1
  }
}

Return JSON only. Do not call tools or run commands.