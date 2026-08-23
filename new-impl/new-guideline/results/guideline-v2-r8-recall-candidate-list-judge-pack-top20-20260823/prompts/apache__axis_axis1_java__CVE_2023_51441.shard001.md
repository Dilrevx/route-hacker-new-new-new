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
      "file": "axis-rt-core/src/main/java/org/apache/axis/transport/http/AxisServlet.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import org.apache.axis.ConfigurationException;\n42: import org.apache.axis.Constants;\n43: import org.apache.axis.Handler;\n44: import org.apache.axis.Message;\n45: import org.apache.axis.MessageContext;\n46: import org.apache.axis.SimpleTargetedChain;\n47: import org.apache.axis.components.logger.LogFactory;\n48: import org.apache.axis.description.OperationDesc;\n49: import org.apache.axis.description.ServiceDesc;\n50: import org.apache.axis.handlers.soap.SOAPService;\n51: import org.apache.axis.security.servlet.ServletSecurityProvider;\n52: import org.apache.axis.utils.JavaUtils;\n53: import org.apache.axis.utils.Messages;\n54: import org.apache.axis.utils.XMLUtils;\n55: import org.apache.commons.logging.Log;\n56: import org.w3c.dom.Element;\n57: \n58: /**\n59:  *\n60:  * @author Doug Davis (dug@us.ibm.com)\n61:  * @author Steve Loughran\n62:  * xdoclet tags are not active yet; keep web.xml in sync.\n63:  * To change the location of the services, change url-pattern in web.xml and\n64:  * set parameter axis.servicesPath in server-config.wsdd. For more information see\n65:  * <a href=\"http://ws.apache.org/axis/java/reference.html\">Axis Reference Guide</a>.\n66:   */\n67: public class AxisServlet extends",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C002",
      "file": "axis-rt-core/src/main/java/org/apache/axis/client/Call.java",
      "lines": {
        "end": 640,
        "start": 561
      },
      "snippet": "561:     static {\n562:         propertyNames.add(USERNAME_PROPERTY);\n563:         propertyNames.add(PASSWORD_PROPERTY);\n564:         propertyNames.add(SESSION_MAINTAIN_PROPERTY);\n565:         propertyNames.add(OPERATION_STYLE_PROPERTY);\n566:         propertyNames.add(SOAPACTION_USE_PROPERTY);\n567:         propertyNames.add(SOAPACTION_URI_PROPERTY);\n568:         propertyNames.add(ENCODINGSTYLE_URI_PROPERTY);\n569:         propertyNames.add(Stub.ENDPOINT_ADDRESS_PROPERTY);\n570:         propertyNames.add(TRANSPORT_NAME);\n571:         propertyNames.add(ATTACHMENT_ENCAPSULATION_FORMAT);\n572:         propertyNames.add(CONNECTION_TIMEOUT_PROPERTY);\n573:         propertyNames.add(CHARACTER_SET_ENCODING);\n574:     }\n575: \n576:     public Iterator getPropertyNames() {\n577:         return propertyNames.iterator();\n578:     }\n579: \n580:     public boolean isPropertySupported(String name) {\n581:         return propertyNames.contains(name) || (!name.startsWith(\"java.\")\n582:                && !name.startsWith(\"javax.\"));\n583:     }\n584: \n585:     /**\n586:      * Set the username.\n587:      *\n588:      * @param username  the new user name\n589:      */\n590:     public void setUsername(String usernam",
      "span_kind": "sliding_window",
      "symbol": "JAXRPCException"
    },
    {
      "candidate_id": "C003",
      "file": "axis-codegen/src/main/java/org/apache/axis/wsdl/toJava/JavaServiceImplWriter.java",
      "lines": {
        "end": 280,
        "start": 201
      },
      "snippet": "201:                 java.net.URLStreamHandler handler = null;\n202:                 String handlerPkgs =\n203:                         System.getProperty(\"java.protocol.handler.pkgs\");\n204: \n205:                 if (handlerPkgs != null) {\n206:                     int protIndex = address.indexOf(\":\");\n207: \n208:                     if (protIndex > 0) {\n209:                         String protocol = address.substring(0,\n210:                                 protIndex);\n211:                         StringTokenizer st =\n212:                                 new StringTokenizer(handlerPkgs, \"|\");\n213: \n214:                         while (st.hasMoreTokens()) {\n215:                             String pkg = st.nextToken();\n216:                             String handlerClass = pkg + \".\" + protocol\n217:                                     + \".Handler\";\n218: \n219:                             try {\n220:                                 Class c = Class.forName(handlerClass);\n221: \n222:                                 handler =\n223:                                         (java.net.URLStreamHandler) c.newInstance();\n224:                                 url = new java.net.URL(null, address,\n225:    ",
      "span_kind": "sliding_window",
      "symbol": "IOException"
    },
    {
      "candidate_id": "C004",
      "file": "axis-rt-core/src/main/java/org/apache/axis/AxisProperties.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2001-2004 The Apache Software Foundation.\n3:  * \n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  * \n8:  *      http://www.apache.org/licenses/LICENSE-2.0\n9:  * \n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: \n17: package org.apache.axis;\n18: \n19: import org.apache.axis.components.logger.LogFactory;\n20: import org.apache.axis.utils.Messages;\n21: import org.apache.commons.discovery.ResourceClassIterator;\n22: import org.apache.commons.discovery.ResourceNameDiscover;\n23: import org.apache.commons.discovery.ResourceNameIterator;\n24: import org.apache.commons.discovery.resource.ClassLoaders;\n25: import org.apache.commons.discovery.resource.classes.DiscoverClasses;\n26: import org.apache.commons.discovery.resource.names.Discove",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C005",
      "file": "axis-rt-core/src/main/java/org/apache/axis/providers/java/RMIProvider.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2001-2004 The Apache Software Foundation.\n3:  * \n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  * \n8:  *      http://www.apache.org/licenses/LICENSE-2.0\n9:  * \n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: \n17: package org.apache.axis.providers.java;\n18: \n19: import org.apache.axis.Constants;\n20: import org.apache.axis.Handler;\n21: import org.apache.axis.MessageContext;\n22: import org.apache.axis.components.logger.LogFactory;\n23: import org.apache.commons.logging.Log;\n24: \n25: import java.rmi.Naming;\n26: import java.rmi.RMISecurityManager;\n27: \n28: /**\n29:  * A basic RMI Provider\n30:  *\n31:  * @author Davanum Srinivas (dims@yahoo.com)\n32:  */\n33: public class RMIProvider extends RPCProvider {\n34:     protected static ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C006",
      "file": "axis-rt-transport-http-javanet/src/main/resources/org/apache/axis/transport/http/javanet/resource.properties",
      "lines": {
        "end": 17,
        "start": 1
      },
      "snippet": "1: # Licensed to the Apache Software Foundation (ASF) under one\n2: # or more contributor license agreements. See the NOTICE file\n3: # distributed with this work for additional information\n4: # regarding copyright ownership. The ASF licenses this file\n5: # to you under the Apache License, Version 2.0 (the\n6: # \"License\"); you may not use this file except in compliance\n7: # with the License. You may obtain a copy of the License at\n8: #\n9: # http://www.apache.org/licenses/LICENSE-2.0\n10: #\n11: # Unless required by applicable law or agreed to in writing,\n12: # software distributed under the License is distributed on an\n13: # \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n14: # KIND, either express or implied. See the License for the\n15: # specific language governing permissions and limitations\n16: # under the License.\n17: userAgentToken=JavaNetHTTPSender/${project.version}",
      "span_kind": "sliding_window",
      "symbol": "Foundation"
    },
    {
      "candidate_id": "C007",
      "file": "axis-rt-jws/src/main/java/org/apache/axis/handlers/JWSHandler.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import java.util.Map;\n42: \n43: import javax.tools.Diagnostic;\n44: import javax.tools.Diagnostic.Kind;\n45: import javax.tools.DiagnosticCollector;\n46: import javax.tools.JavaCompiler;\n47: import javax.tools.JavaCompiler.CompilationTask;\n48: import javax.tools.JavaFileObject;\n49: import javax.tools.StandardJavaFileManager;\n50: import javax.tools.StandardLocation;\n51: import javax.tools.ToolProvider;\n52: \n53: /** A <code>JWSHandler</code> sets the target service and JWS filename\n54:  * in the context depending on the JWS configuration and the target URL.\n55:  *\n56:  * @author Glen Daniels (gdaniels@allaire.com)\n57:  * @author Doug Davis (dug@us.ibm.com)\n58:  * @author Sam Ruby (rubys@us.ibm.com)\n59:  */\n60: public class JWSHandler extends BasicHandler\n61: {\n62:     protected static Log log =\n63:         LogFactory.getLog(JWSHandler.class.getName());\n64: \n65:     public final String OPTION_JWS_FILE_EXTENSION = \"extension\";\n66:     public final String DEFAULT_JWS_FILE_EXTENSION = Constants.JWS_DEFAULT_FILE_EXTENSION;\n67: \n68:     private final Map/*<String,SOAPService>*/ soapServices = new HashMap();\n69:     private final Map/*<String,ClassLoader>*/ classloaders = new Hashtable();\n7",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C008",
      "file": "axis-rt-core/src/main/java/org/apache/axis/deployment/wsdd/WSDDJAXRPCHandlerInfo.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2001-2004 The Apache Software Foundation.\n3:  * \n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  * \n8:  *      http://www.apache.org/licenses/LICENSE-2.0\n9:  * \n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: package org.apache.axis.deployment.wsdd;\n17: \n18: import org.apache.axis.encoding.SerializationContext;\n19: import org.apache.axis.utils.Messages;\n20: import org.apache.axis.utils.XMLUtils;\n21: import org.w3c.dom.Element;\n22: import org.xml.sax.helpers.AttributesImpl;\n23: \n24: import javax.xml.namespace.QName;\n25: import java.io.IOException;\n26: import java.util.HashMap;\n27: import java.util.Iterator;\n28: import java.util.Map;\n29: import java.util.Set;\n30: \n31: \n32: /**\n33:  *\n34:  */\n35: public class WSDDJAXRPCHand",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C009",
      "file": "axis-rt-jws/src/main/java/org/apache/axis/handlers/JWSHandler.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2001-2004 The Apache Software Foundation.\n3:  * \n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  * \n8:  *      http://www.apache.org/licenses/LICENSE-2.0\n9:  * \n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: \n17: package org.apache.axis.handlers;\n18: \n19: import org.apache.axis.AxisFault;\n20: import org.apache.axis.Constants;\n21: import org.apache.axis.MessageContext;\n22: import org.apache.axis.components.logger.LogFactory;\n23: import org.apache.axis.constants.Scope;\n24: import org.apache.axis.handlers.soap.SOAPService;\n25: import org.apache.axis.providers.java.RPCProvider;\n26: import org.apache.axis.utils.ClasspathUtils;\n27: import org.apache.axis.utils.JWSClassLoader;\n28: import org.apache.axis.utils.Messages;\n29: imp",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C010",
      "file": "axis-rt-compat/src/main/java/org/apache/axis/transport/http/SimpleAxisWorker.java",
      "lines": {
        "end": 320,
        "start": 241
      },
      "snippet": "241:                     if (\"wsdl\".equalsIgnoreCase(params))\n242:                         doWsdl = true;\n243: \n244:                     if (params.startsWith(\"method=\")) {\n245:                         methodName = params.substring(7);\n246:                     }\n247:                 }\n248: \n249:                 // Real and relative paths are the same for the\n250:                 // SimpleAxisServer\n251:                 msgContext.setProperty(Constants.MC_REALPATH,\n252:                         fileName.toString());\n253:                 msgContext.setProperty(Constants.MC_RELATIVE_PATH,\n254:                         fileName.toString());\n255:                 msgContext.setProperty(Constants.MC_JWS_CLASSDIR,\n256:                         \"jwsClasses\");\n257:                 msgContext.setProperty(Constants.MC_HOME_DIR, \".\");\n258: \n259:                 // !!! Fix string concatenation\n260:                 String url = \"http://\" + getLocalHost() + \":\" +\n261:                         server.getServerSocket().getLocalPort() + \"/\" +\n262:                         fileName.toString();\n263:                 msgContext.setProperty(MessageContext.TRANS_URL, url);\n264: \n265:                 String file",
      "span_kind": "sliding_window",
      "symbol": ""
    }
  ],
  "guideline": "HCVR type: iris\nGuideline: Trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs. Report code paths where the lookup scheme, authority, object factory, object type, and network destination are not constrained before lookup. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should bind lookup inputs to trusted constants or allowlists, restrict schemes and destinations, and disable remote object factories.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 1
  }
}

Return JSON only. Do not call tools or run commands.