# Axis SOAP/DIME Root Default-WAR HTTP Validation

Generated: 2026-08-21

## Target

- Repository: `apache/axis-axis1-java`
- Revision: `2c0d66018480e0cb73d5005c99c68ef55558d2a3`
- Deployment: default Axis WAR built from latest HEAD, deployed under `/axis` with Jetty runner.
- Service endpoint: default `Version` service at `/axis/services/Version`.
- Request path: real HTTP `POST /axis/services/Version` with `Content-Type: application/dime`.

## Test Design

The test used a valid single-record DIME message whose root record type is `text/xml`. The root SOAP document contains a large text node inside the SOAP body. No custom attachment-consuming service was deployed for this test.

Two constrained-heap runs were executed:

- `-Xmx24m` on port `31092`
- `-Xmx64m` on port `31093`

Each run first verified the default WSDL endpoint returned `HTTP/1.1 200 OK`, then sent root SOAP record sizes of 1 MiB, 8 MiB, and 32 MiB. After each case it checked the WSDL endpoint again to distinguish request-level OOM from full process death.

## Results

### `-Xmx24m`

| Root SOAP size | HTTP body length | Response | Post-case WSDL | Interpretation |
| ---: | ---: | --- | --- | --- |
| 1 MiB | 1,048,600 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` | Baseline accepted. |
| 8 MiB | 8,388,632 | `HTTP/1.1 500 Server Error` with `java.lang.OutOfMemoryError: Java heap space` in SOAP Fault | `HTTP/1.1 200 OK` | Request-level heap OOM. |
| 32 MiB | 33,554,456 | `HTTP/1.1 500 Server Error` with `java.lang.OutOfMemoryError: Java heap space` in SOAP Fault | `HTTP/1.1 200 OK` | Request-level heap OOM. |

### `-Xmx64m`

| Root SOAP size | HTTP body length | Response | Post-case WSDL | Interpretation |
| ---: | ---: | --- | --- | --- |
| 1 MiB | 1,048,600 | `HTTP/1.1 200 OK` | `HTTP/1.1 200 OK` | Baseline accepted. |
| 8 MiB | 8,388,632 | `HTTP/1.1 500 Server Error` with `java.lang.OutOfMemoryError: Java heap space` in SOAP Fault | `HTTP/1.1 200 OK` | Request-level heap OOM. |
| 32 MiB | 33,554,456 | `HTTP/1.1 500 Server Error` with `java.lang.OutOfMemoryError: Java heap space` in SOAP Fault | `HTTP/1.1 200 OK` | Request-level heap OOM. |

## Stack Evidence

The server log for the `-Xmx24m` run recorded the following stack for both 8 MiB and 32 MiB cases:

```text
java.lang.OutOfMemoryError: Java heap space
  at java.base/java.util.Arrays.copyOf(Arrays.java:3841)
  at java.base/java.io.CharArrayWriter.write(CharArrayWriter.java:110)
  at org.apache.axis.message.SOAPHandler.characters(SOAPHandler.java:169)
  at org.apache.axis.encoding.DeserializationContext.characters(DeserializationContext.java:983)
  at org.apache.xerces.parsers.AbstractSAXParser.characters(Unknown Source)
  at org.apache.xerces.impl.XMLDocumentFragmentScannerImpl.scanContent(Unknown Source)
  at org.apache.axis.encoding.DeserializationContext.parse(DeserializationContext.java:241)
  at org.apache.axis.SOAPPart.getAsSOAPEnvelope(SOAPPart.java:696)
  at org.apache.axis.Message.getSOAPEnvelope(Message.java:435)
  at org.apache.axis.server.AxisServer.initSOAPConstants(AxisServer.java:345)
  at org.apache.axis.server.AxisServer.invoke(AxisServer.java:279)
  at org.apache.axis.transport.http.AxisServlet.doPost(AxisServlet.java:684)
```

## Conclusion

The default Axis WAR and default `Version` service accept valid DIME HTTP requests whose root SOAP record is attacker-controlled. Under constrained JVM heaps, an 8 MiB or 32 MiB root SOAP body triggers a request-level `OutOfMemoryError: Java heap space` during Axis SOAP parsing. The service process remained alive in this test and continued serving WSDL after each OOM response, so the demonstrated impact is request-level heap exhaustion and repeated-request DoS potential rather than one-shot JVM process termination.

This evidence is stronger than the attachment-temp-file issue because it does not require a custom application service to call `getAttachments()`. It is still distinct from the attachment materialization finding: attachment disk growth remains dependent on a service that accesses attachments, while SOAP-root heap pressure is on the default request processing path.
