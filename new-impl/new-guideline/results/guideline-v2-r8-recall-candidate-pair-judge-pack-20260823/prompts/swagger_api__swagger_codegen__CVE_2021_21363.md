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
      "file": "modules/swagger-codegen/src/main/java/io/swagger/codegen/AbstractGenerator.java",
      "label": "A",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: package io.swagger.codegen;\n2: \n3: import java.io.BufferedWriter;\n4: import java.io.File;\n5: import java.io.FileInputStream;\n6: import java.io.FileOutputStream;\n7: import java.io.IOException;\n8: import java.io.InputStream;\n9: import java.io.InputStreamReader;\n10: import java.io.OutputStreamWriter;\n11: import java.io.Reader;\n12: import java.io.Writer;\n13: import java.util.Scanner;\n14: import java.util.regex.Pattern;\n15: \n16: import org.apache.commons.lang3.StringUtils;\n17: import org.slf4j.Logger;\n18: import org.slf4j.LoggerFactory;\n19: \n20: public abstract class AbstractGenerator {\n21:     private static final Logger LOGGER = LoggerFactory.getLogger(AbstractGenerator.class);\n22: \n23:     @SuppressWarnings(\"static-method\")\n24:     public File writeToFile(String filename, String contents) throws IOException {\n25:         LOGGER.info(\"writing file \" + filename);\n26:         File output = new File(filename);\n27: \n28:         if (output.getParent() != null && !new File(output.getParent()).exists()) {\n29:             File parent = new File(output.getParent());\n30:             parent.mkdirs();\n31:         }\n32:         Writer out = new BufferedWriter(new OutputStreamWriter(\n33:                 new FileOutputStream(output), \"UTF-8\"));\n34: \n35:         out.write(contents);\n36:         out.close();\n37:         return output;\n38:     }\n39: \n40:     public String readTemplate(String name) {\n41:         try {\n42:             Reader reader = getTemplateReader(name);\n43:             if (reader == null) {\n44:                 throw new RuntimeException(\"no file found\");\n45:             }\n46:             Scanner s = new Scanner(reader).useDelimiter(\"\\\\A\");\n47:             return s.hasNext() ? s.next() : \"\";\n48:         } catch (Exception e) {\n49:             LOGGER.error(e.getMessage());\n50:         }\n51:         throw new RuntimeException(\"can't load template \" + name);\n52:     }\n53: \n54:     public Reader getTemplateReader(String name) {\n55:         try {\n56:             InputStream is = this.getClass().getClassLoader().getResourceAsStream(getCPResourcePath(name));\n57:             if (is == null) {\n58:                 is = new FileInputStream(new File(name)); // May throw but never return a null value\n59:             }\n60:             return new InputStreamReader(is, \"UTF-8\");\n61:         } catch (Exception e) {\n62:             LOGGER.error(e.getMessage());\n63:         }\n64:         throw new RuntimeException(\"can't load template \" + name);\n65:     }\n66: \n67:     private String buildLibraryFilePath(String dir, String library, String file) {\n68:         return dir + File.separator + \"libraries\" + File.separator + library + File.separator + file;\n69:     }\n70: \n71:     /**\n72:      * Get the template file path with template dir prepended, and use the\n73:      * library template if exists.\n74:      *\n75:      * @param config Codegen config\n76:      * @param templateFile Template file\n77:      * @return String Full template file path\n78:      */\n79:     public String getFullTemplateFile(CodegenConfig config, String templateFile) {\n80:         //1st the code will check if there's a <template folder>/libraries/<library> folder containing the file",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "file": "modules/swagger-generator/src/main/java/io/swagger/generator/online/Generator.java",
      "label": "B",
      "lines": {
        "end": 186,
        "start": 121
      },
      "snippet": "121:         } catch (RuntimeException e) {\n122:             throw new BadRequestException(\"Unsupported target \" + language + \" supplied\");\n123:         }\n124: \n125:         if (opts.getOptions() != null) {\n126:             codegenConfig.additionalProperties().putAll(opts.getOptions());\n127:             codegenConfig.additionalProperties().put(\"swagger\", swagger);\n128:         }\n129: \n130:         codegenConfig.setOutputDir(outputFolder);\n131: \n132:         LOGGER.debug(Json.pretty(clientOpts));\n133: \n134:         clientOptInput.setConfig(codegenConfig);\n135: \n136:         try {\n137:             List<File> files = new Codegen().opts(clientOptInput).generate();\n138:             if (files.size() > 0) {\n139:                 List<File> filesToAdd = new ArrayList<File>();\n140:                 LOGGER.debug(\"adding to \" + outputFolder);\n141:                 filesToAdd.add(new File(outputFolder));\n142:                 ZipUtil zip = new ZipUtil();\n143:                 zip.compressFiles(filesToAdd, outputFilename);\n144:             } else {\n145:                 throw new BadRequestException(\n146:                         \"A target generation was attempted, but no files were created!\");\n147:             }\n148:             for (File file : files) {\n149:                 try {\n150:                     file.delete();\n151:                 } catch (Exception e) {\n152:                     LOGGER.error(\"unable to delete file \" + file.getAbsolutePath());\n153:                 }\n154:             }\n155:             try {\n156:                 new File(outputFolder).delete();\n157:             } catch (Exception e) {\n158:                 LOGGER.error(\"unable to delete output folder \" + outputFolder);\n159:             }\n160:         } catch (Exception e) {\n161:             throw new BadRequestException(\"Unable to build target: \" + e.getMessage());\n162:         }\n163:         return outputFilename;\n164:     }\n165: \n166:     public static InputOption clientOptions(@SuppressWarnings(\"unused\") String language) {\n167:         return null;\n168:     }\n169: \n170:     public static InputOption serverOptions(@SuppressWarnings(\"unused\") String language) {\n171:         return null;\n172:     }\n173: \n174:     protected static File getTmpFolder() {\n175:         try {\n176:             File outputFolder = File.createTempFile(\"codegen-\", \"-tmp\");\n177:             outputFolder.delete();\n178:             outputFolder.mkdir();\n179:             outputFolder.deleteOnExit();\n180:             return outputFolder;\n181:         } catch (Exception e) {\n182:             e.printStackTrace();\n183:             return null;\n184:         }\n185:     }\n186: }",
      "span_kind": "sliding_window",
      "symbol": "BadRequestException"
    }
  ],
  "guideline": "HCVR type: toctou_check_use_race\nGuideline: Trace temporary file or directory names created in shared writable locations into manual temporary directory creation sequences such as createTempFile, delete, then mkdir or mkdirs. Report code paths where the temporary path is released between creation and directory creation, allowing another actor to replace or pre-create it before use. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 10 historical CVE example(s), not as a project-specific signature. A safe implementation should use an atomic temporary-directory API such as Files.createTempDirectory and avoid delete-then-mkdir sequences.",
  "judge_mode": "recall_candidate_pair_advisory"
}

Return JSON only. Do not call tools or run commands.