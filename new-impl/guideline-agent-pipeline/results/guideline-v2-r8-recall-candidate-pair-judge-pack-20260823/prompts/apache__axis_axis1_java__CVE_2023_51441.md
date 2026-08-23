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
      "file": "axis-rt-core/src/main/java/org/apache/axis/client/ServiceFactory.java",
      "label": "A",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2001-2004 The Apache Software Foundation.\n3:  * \n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  * \n8:  *      http://www.apache.org/licenses/LICENSE-2.0\n9:  * \n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: \n17: package org.apache.axis.client;\n18: \n19: import org.apache.axis.EngineConfiguration;\n20: import org.apache.axis.configuration.EngineConfigurationFactoryFinder;\n21: import org.apache.axis.utils.ClassUtils;\n22: import org.apache.axis.utils.Messages;\n23: \n24: import javax.naming.Context;\n25: import javax.naming.InitialContext;\n26: import javax.naming.Name;\n27: import javax.naming.NamingException;\n28: import javax.naming.RefAddr;\n29: import javax.naming.Reference;\n30: import javax.naming.spi.ObjectFactory;\n31: import javax.xml.namespace.QName;\n32: import javax.xml.rpc.ServiceException;\n33: import java.lang.reflect.Constructor;\n34: import java.net.URL;\n35: import java.util.Hashtable;\n36: import java.util.Map;\n37: import java.util.Properties;\n38: \n39: /**\n40:  * Helper class for obtaining Services from JNDI.\n41:  *\n42:  * !!! WORK IN PROGRESS\n43:  * \n44:  * @author Glen Daniels (gdaniels@apache.org)\n45:  */ \n46: \n47: public class ServiceFactory extends javax.xml.rpc.ServiceFactory\n48:         implements ObjectFactory\n49: {\n50:     // Constants for RefAddrs in the Reference.\n51:     public static final String SERVICE_CLASSNAME  = \"service classname\";\n52:     public static final String WSDL_LOCATION      = \"WSDL location\";\n53:     public static final String MAINTAIN_SESSION   = \"maintain session\";\n54:     public static final String SERVICE_NAMESPACE  = \"service namespace\";\n55:     public static final String SERVICE_LOCAL_PART = \"service local part\";\n56:     public static final String SERVICE_IMPLEMENTATION_NAME_PROPERTY = \"serviceImplementationName\";\n57: \n58:     private static final String SERVICE_IMPLEMENTATION_SUFFIX = \"Locator\";\n59: \n60:     private static EngineConfiguration _defaultEngineConfig = null;\n61: \n62:     private static ThreadLocal threadDefaultConfig = new ThreadLocal();\n63: \n64:     public static void setThreadDefaultConfig(EngineConfiguration config)\n65:     {\n66:         threadDefaultConfig.set(config);\n67:     }\n68:     \n69:     private static EngineConfiguration getDefaultEngineConfig() {\n70:         if (_defaultEngineConfig == null) {\n71:             _defaultEngineConfig =\n72:                 EngineConfigurationFactoryFinder.newFactory().getClientEngineConfig();\n73:         }\n74:         return _defaultEngineConfig;\n75:     }\n76: \n77:     /**\n78:      * Obtain an AxisClient reference, using JNDI if possible, otherwise\n79:      * creating one using the standard Axis configuration pattern.  If we\n80:      * end up creating one and do have JNDI access, bind it to the passed",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "file": "axis-rt-jws/src/main/java/org/apache/axis/handlers/JWSHandler.java",
      "label": "B",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2001-2004 The Apache Software Foundation.\n3:  * \n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  * \n8:  *      http://www.apache.org/licenses/LICENSE-2.0\n9:  * \n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: \n17: package org.apache.axis.handlers;\n18: \n19: import org.apache.axis.AxisFault;\n20: import org.apache.axis.Constants;\n21: import org.apache.axis.MessageContext;\n22: import org.apache.axis.components.logger.LogFactory;\n23: import org.apache.axis.constants.Scope;\n24: import org.apache.axis.handlers.soap.SOAPService;\n25: import org.apache.axis.providers.java.RPCProvider;\n26: import org.apache.axis.utils.ClasspathUtils;\n27: import org.apache.axis.utils.JWSClassLoader;\n28: import org.apache.axis.utils.Messages;\n29: import org.apache.axis.utils.XMLUtils;\n30: import org.apache.commons.logging.Log;\n31: import org.w3c.dom.Document;\n32: import org.w3c.dom.Element;\n33: \n34: import java.io.File;\n35: import java.io.FileNotFoundException;\n36: import java.io.FileReader;\n37: import java.io.FileWriter;\n38: import java.util.Collections;\n39: import java.util.HashMap;\n40: import java.util.Hashtable;\n41: import java.util.Map;\n42: \n43: import javax.tools.Diagnostic;\n44: import javax.tools.Diagnostic.Kind;\n45: import javax.tools.DiagnosticCollector;\n46: import javax.tools.JavaCompiler;\n47: import javax.tools.JavaCompiler.CompilationTask;\n48: import javax.tools.JavaFileObject;\n49: import javax.tools.StandardJavaFileManager;\n50: import javax.tools.StandardLocation;\n51: import javax.tools.ToolProvider;\n52: \n53: /** A <code>JWSHandler</code> sets the target service and JWS filename\n54:  * in the context depending on the JWS configuration and the target URL.\n55:  *\n56:  * @author Glen Daniels (gdaniels@allaire.com)\n57:  * @author Doug Davis (dug@us.ibm.com)\n58:  * @author Sam Ruby (rubys@us.ibm.com)\n59:  */\n60: public class JWSHandler extends BasicHandler\n61: {\n62:     protected static Log log =\n63:         LogFactory.getLog(JWSHandler.class.getName());\n64: \n65:     public final String OPTION_JWS_FILE_EXTENSION = \"extension\";\n66:     public final String DEFAULT_JWS_FILE_EXTENSION = Constants.JWS_DEFAULT_FILE_EXTENSION;\n67: \n68:     private final Map/*<String,SOAPService>*/ soapServices = new HashMap();\n69:     private final Map/*<String,ClassLoader>*/ classloaders = new Hashtable();\n70: \n71:     /**\n72:      * Just set up the service, the inner service will do the rest...\n73:      */ \n74:     public void invoke(MessageContext msgContext) throws AxisFault\n75:     {\n76:         if (log.isDebugEnabled()) {\n77:             log.debug(\"Enter: JWSHandler::invoke\");\n78:         }\n79: \n80:         try {",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: iris\nGuideline: Trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs. Report code paths where the lookup scheme, authority, object factory, object type, and network destination are not constrained before lookup. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should bind lookup inputs to trusted constants or allowlists, restrict schemes and destinations, and disable remote object factories.",
  "judge_mode": "recall_candidate_pair_advisory"
}

Return JSON only. Do not call tools or run commands.