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
      "file": "axis-rt-core/src/main/java/org/apache/axis/transport/http/HTTPSender.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import java.io.IOException;\n42: import java.io.InputStream;\n43: import java.io.OutputStream;\n44: import java.net.Socket;\n45: import java.net.URL;\n46: import java.util.Enumeration;\n47: import java.util.Hashtable;\n48: import java.util.Iterator;\n49: import java.util.ArrayList;\n50: \n51: /**\n52:  * This is meant to be used on a SOAP Client to call a SOAP server.\n53:  *\n54:  * @author Doug Davis (dug@us.ibm.com)\n55:  * @author Davanum Srinivas (dims@yahoo.com)\n56:  */\n57: public class HTTPSender extends BasicHandler {\n58: \n59:     protected static Log log = LogFactory.getLog(HTTPSender.class.getName());\n60: \n61:     private static final String ACCEPT_HEADERS = \n62:         HTTPConstants.HEADER_ACCEPT + //Limit to the types that are meaningful to us.\n63:         \": \" +\n64:         HTTPConstants.HEADER_ACCEPT_APPL_SOAP +\n65:         \", \" +\n66:         HTTPConstants.HEADER_ACCEPT_APPLICATION_DIME +\n67:         \", \" +\n68:         HTTPConstants.HEADER_ACCEPT_MULTIPART_RELATED +\n69:         \", \" +\n70:         HTTPConstants.HEADER_ACCEPT_TEXT_ALL +\n71:         \"\\r\\n\" +\n72:         HTTPConstants.HEADER_USER_AGENT +   //Tell who we are.\n73:         \": \" +\n74:         Messages.getMessage(\"axis",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C012",
      "file": "axis-rt-core/src/main/java/org/apache/axis/components/net/JSSESocketFactory.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import javax.naming.directory.Attributes;\n42: import javax.naming.ldap.LdapName;\n43: import javax.naming.ldap.Rdn;\n44: import javax.net.ssl.SSLException;\n45: import javax.net.ssl.SSLSession;\n46: import javax.net.ssl.SSLSocket;\n47: import javax.net.ssl.SSLSocketFactory;\n48: \n49: import org.apache.axis.utils.Messages;\n50: import org.apache.axis.utils.StringUtils;\n51: import org.apache.axis.utils.XMLUtils;\n52: \n53: \n54: /**\n55:  * SSL socket factory. It _requires_ a valid RSA key and\n56:  * JSSE. (borrowed code from tomcat)\n57:  * \n58:  * THIS CODE STILL HAS DEPENDENCIES ON sun.* and com.sun.*\n59:  *\n60:  * @author Davanum Srinivas (dims@yahoo.com)\n61:  */\n62: public class JSSESocketFactory extends DefaultSocketFactory implements SecureSocketFactory {\n63: \n64:     // This is a a sorted list, if you insert new elements do it orderdered.\n65:     private final static String[] BAD_COUNTRY_2LDS =\n66:         {\"ac\", \"co\", \"com\", \"ed\", \"edu\", \"go\", \"gouv\", \"gov\", \"info\",\n67:             \"lg\", \"ne\", \"net\", \"or\", \"org\"};\n68:     /** Field sslFactory           */\n69:     protected SSLSocketFactory sslFactory = null;\n70: \n71:     /**\n72:      * Constructor JSSESocketFactory\n73:      *\n74:   ",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C013",
      "file": "axis-rt-core/src/main/java/org/apache/axis/AxisProperties.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81:     private static DiscoverMappedNames mappedNames;\n82:     private static NameDiscoverers nameDiscoverer;\n83:     private static ClassLoaders loaders;\n84: \n85:     public static void setClassOverrideProperty(Class clazz, String propertyName) {\n86:         getAlternatePropertyNameDiscoverer()\n87:             .addClassToPropertyNameMapping(clazz.getName(), propertyName);\n88:     }\n89: \n90:     public static void setClassDefault(Class clazz, String defaultName) {\n91:         getMappedNames().map(clazz.getName(), defaultName);\n92:     }\n93: \n94:     public static void setClassDefaults(Class clazz, String[] defaultNames) {\n95:         getMappedNames().map(clazz.getName(), defaultNames);\n96:     }\n97: \n98:     public static synchronized ResourceNameDiscover getNameDiscoverer() {\n99:         if (nameDiscoverer == null) {\n100:             nameDiscoverer = new NameDiscoverers();\n101:             nameDiscoverer.addResourceNameDiscover(getAlternatePropertyNameDiscoverer());\n102:             nameDiscoverer.addResourceNameDiscover(new DiscoverNamesInManagedProperties());\n103:             nameDiscoverer.addResourceNameDiscover(new DiscoverServiceNames(getClassLoaders()));\n104:             n",
      "span_kind": "sliding_window",
      "symbol": "AxisProperties"
    },
    {
      "candidate_id": "C014",
      "file": "axis-rt-core/src/main/java/org/apache/axis/MessageContext.java",
      "lines": {
        "end": 920,
        "start": 841
      },
      "snippet": "841:     /** This String is the URL that the message came to.\n842:      */\n843:     public static final String TRANS_URL           = \"transport.url\";\n844: \n845:     /** Has a quit been requested? Hackish... but useful... -- RobJ */\n846:     public static final String QUIT_REQUESTED = \"quit.requested\";\n847: \n848:     /** Place to store an AuthenticatedUser. */\n849:     public static final String AUTHUSER            = \"authenticatedUser\";\n850: \n851:     /** If on the client - this is the Call object. */\n852:     public static final String CALL                = \"call_object\" ;\n853: \n854:     /** Are we doing Msg vs RPC? - For Java Binding. */\n855:     public static final String IS_MSG              = \"isMsg\" ;\n856: \n857:     /** The directory where in coming attachments are created. */\n858:     public static final String ATTACHMENTS_DIR   = \"attachments.directory\" ;\n859: \n860:     /** A boolean param, to control whether we accept missing parameters\n861:      * as nulls or refuse to acknowledge them.\n862:      */\n863:     public final static String ACCEPTMISSINGPARAMS = \"acceptMissingParams\";\n864: \n865:     /** The value of the property is used by service WSDL generation (aka ?WSDL)\n866",
      "span_kind": "sliding_window",
      "symbol": "deffinition"
    },
    {
      "candidate_id": "C015",
      "file": "axis-rt-transport-http-javanet/src/main/java/org/apache/axis/transport/http/javanet/JavaNetHTTPSender.java",
      "lines": {
        "end": 120,
        "start": 41
      },
      "snippet": "41: import org.apache.axis.transport.http.HTTPConstants;\n42: import org.apache.commons.logging.Log;\n43: \n44: /**\n45:  * Pivot handler for the HTTP transport based on the {@link HttpURLConnection} API.\n46:  * \n47:  * @author Andreas Veithen\n48:  */\n49: public class JavaNetHTTPSender extends BasicHandler {\n50:     private static final long serialVersionUID = 1L;\n51: \n52:     private static final Log log = LogFactory.getLog(JavaNetHTTPSender.class.getName());\n53:     \n54:     /**\n55:      * The value of the <tt>User-Agent</tt> header. It is composed of the Axis version, the version\n56:      * of JavaNetHTTPSender (which may be different, because it may work with older Axis versions as\n57:      * well) and the Java version (which is important because we are using the HTTP client of the\n58:      * JRE).\n59:      */\n60:     private static final String userAgent = Messages.getMessage(\"axisUserAgent\") + \" \"\n61:             + Messages.getMessage(\"userAgentToken\") + \" Java/\" + System.getProperty(\"java.version\");\n62:     \n63:     public void invoke(MessageContext msgContext) throws AxisFault {\n64:         try {\n65:             Message request = msgContext.getRequestMessage();\n66:             ",
      "span_kind": "sliding_window",
      "symbol": "Foundation"
    },
    {
      "candidate_id": "C016",
      "file": "axis-rt-transport-http-javanet/src/main/java/org/apache/axis/transport/http/javanet/JavaNetHTTPSender.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Licensed to the Apache Software Foundation (ASF) under one\n3:  * or more contributor license agreements. See the NOTICE file\n4:  * distributed with this work for additional information\n5:  * regarding copyright ownership. The ASF licenses this file\n6:  * to you under the Apache License, Version 2.0 (the\n7:  * \"License\"); you may not use this file except in compliance\n8:  * with the License. You may obtain a copy of the License at\n9:  *\n10:  * http://www.apache.org/licenses/LICENSE-2.0\n11:  *\n12:  * Unless required by applicable law or agreed to in writing,\n13:  * software distributed under the License is distributed on an\n14:  * \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n15:  * KIND, either express or implied. See the License for the\n16:  * specific language governing permissions and limitations\n17:  * under the License.\n18:  */\n19: package org.apache.axis.transport.http.javanet;\n20: \n21: import java.io.IOException;\n22: import java.io.InputStream;\n23: import java.io.InputStreamReader;\n24: import java.io.OutputStream;\n25: import java.io.Reader;\n26: import java.net.HttpURLConnection;\n27: import java.net.URL;\n28: \n29: import javax.xml.soap.MimeHeaders;\n30: impo",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C017",
      "file": "axis-rt-core/src/main/java/org/apache/axis/components/net/JSSESocketFactory.java",
      "lines": {
        "end": 80,
        "start": 1
      },
      "snippet": "1: /*\n2:  * Copyright 2001-2004 The Apache Software Foundation.\n3:  * \n4:  * Licensed under the Apache License, Version 2.0 (the \"License\");\n5:  * you may not use this file except in compliance with the License.\n6:  * You may obtain a copy of the License at\n7:  * \n8:  *      http://www.apache.org/licenses/LICENSE-2.0\n9:  * \n10:  * Unless required by applicable law or agreed to in writing, software\n11:  * distributed under the License is distributed on an \"AS IS\" BASIS,\n12:  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n13:  * See the License for the specific language governing permissions and\n14:  * limitations under the License.\n15:  */\n16: package org.apache.axis.components.net;\n17: \n18: import java.io.BufferedWriter;\n19: import java.io.IOException;\n20: import java.io.InputStream;\n21: import java.io.OutputStream;\n22: import java.io.OutputStreamWriter;\n23: import java.io.PrintWriter;\n24: import java.net.Socket;\n25: import java.security.cert.Certificate;\n26: import java.security.cert.CertificateParsingException;\n27: import java.security.cert.X509Certificate;\n28: import java.util.ArrayList;\n29: import java.util.Arrays;\n30: import java.util.Collection;\n31",
      "span_kind": "sliding_window",
      "symbol": ""
    },
    {
      "candidate_id": "C018",
      "file": "axis-rt-core/src/main/java/org/apache/axis/transport/http/AxisServlet.java",
      "lines": {
        "end": 160,
        "start": 81
      },
      "snippet": "81:     private static Log exceptionLog =\n82:             LogFactory.getLog(Constants.EXCEPTION_LOG_CATEGORY);\n83: \n84:     public static final String INIT_PROPERTY_TRANSPORT_NAME =\n85:             \"transport.name\";\n86: \n87:     public static final String INIT_PROPERTY_USE_SECURITY =\n88:             \"use-servlet-security\";\n89:     public static final String INIT_PROPERTY_ENABLE_LIST =\n90:             \"axis.enableListQuery\";\n91: \n92:     public static final String INIT_PROPERTY_JWS_CLASS_DIR =\n93:             \"axis.jws.servletClassDir\";\n94: \n95:     // This will turn off the list of available services\n96:     public static final String INIT_PROPERTY_DISABLE_SERVICES_LIST =\n97:             \"axis.disableServiceList\";\n98: \n99:     // Location of the services as defined by the servlet-mapping in web.xml\n100:     public static final String INIT_PROPERTY_SERVICES_PATH =\n101:             \"axis.servicesPath\";\n102: \n103:     // These have default values.\n104:     private String transportName;\n105: \n106:     private Handler transport;\n107: \n108:     private ServletSecurityProvider securityProvider = null;\n109: \n110:     private String servicesPath;\n111: \n112:     /**\n113:      * cache of logg",
      "span_kind": "sliding_window",
      "symbol": "AxisServlet"
    },
    {
      "candidate_id": "C019",
      "file": "axis-rt-core/src/main/java/org/apache/axis/transport/http/AxisServlet.java",
      "lines": {
        "end": 240,
        "start": 161
      },
      "snippet": "161:                                                  INIT_PROPERTY_USE_SECURITY, null))) {\n162:             securityProvider = new ServletSecurityProvider();\n163:         }\n164: \n165:         enableList =\n166:                 JavaUtils.isTrueExplicitly(getOption(context,\n167:                 INIT_PROPERTY_ENABLE_LIST, null));\n168: \n169:         jwsClassDir = getOption(context, INIT_PROPERTY_JWS_CLASS_DIR, null);\n170: \n171:         // Should we list services?\n172:         disableServicesList = JavaUtils.isTrue(getOption(context,\n173:                 INIT_PROPERTY_DISABLE_SERVICES_LIST, \"false\"));\n174: \n175:         servicesPath = getOption(context, INIT_PROPERTY_SERVICES_PATH,\n176:                                  \"/services/\");\n177: \n178:         /**\n179:          * There are DEFINATE problems here if\n180:          * getHomeDir and/or getDefaultJWSClassDir return null\n181:          * (as they could with WebLogic).\n182:          * This needs to be reexamined in the future, but this\n183:          * should fix any NPE's in the mean time.\n184:          */\n185:         if (jwsClassDir != null) {\n186:             if (getHomeDir() != null && !new File(jwsClassDir).isAbsolute()) {\n187:   ",
      "span_kind": "sliding_window",
      "symbol": "init"
    },
    {
      "candidate_id": "C020",
      "file": "src/site/xdoc/reference.xml",
      "lines": {
        "end": 1064,
        "start": 1001
      },
      "snippet": "1001: <dt>HTTPAuth</dt>\n1002: <dd>The HTTPAuthHandler takes HTTP-specific authentication information (right now, just Basic authentication) and turns it into generic MessageContext properties for username and password</dd>\n1003: \n1004: <dt>SimpleAuthenticationHandler</dt>\n1005: <dd>The SimpleAuthentication handler passes a MessageContext to a SecurityProvider (see org.apache.axis.security) to authenticate the user using whatever information the SecurityProvider wants (right now, just the username and password).</dd>\n1006: \n1007: <dt>SimpleAuthorizationHandler</dt>\n1008: <dd>This handler, typically deployed alongside the SimpleAuthenticationHandler (a chain called \"authChecks\" is predefined for just this combination), checks to make sure that the currently authenticated user satisfies one of the allowed roles for the target service. Throws a Fault if access is denied.</dd>\n1009: \n1010: <dt>MD5AttachHandler</dt>\n1011: <dd>Undocumented, uncalled, untested handler that generates an MD5 hash of attachment information and adds the value as an attribute in the soap body.</dd>\n1012: \n1013: <dt>URLMapper</dt>\n1014: <dd>The URLMapper, an HTTP-specific handler, usually goes on HTTP transport ",
      "span_kind": "sliding_window",
      "symbol": "environment"
    }
  ],
  "guideline": "HCVR type: iris\nGuideline: Trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs. Report code paths where the lookup scheme, authority, object factory, object type, and network destination are not constrained before lookup. Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. Treat this as a reusable mechanism-level pattern derived from 6 historical CVE example(s), not as a project-specific signature. A safe implementation should bind lookup inputs to trusted constants or allowlists, restrict schemes and destinations, and disable remote object factories.",
  "judge_mode": "recall_candidate_list_advisory",
  "shard": {
    "candidate_count": 10,
    "shard_count": 2,
    "shard_index": 2
  }
}

Return JSON only. Do not call tools or run commands.