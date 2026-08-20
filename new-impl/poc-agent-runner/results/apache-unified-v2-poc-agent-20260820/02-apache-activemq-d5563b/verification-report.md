# Independent Verification Report — apache_001

## Verdict

**NOT_VULNERABLE** for a new vendor report.

The candidate describes a real unsafe-deserialization condition on the requested
historical revision, but that revision is the released **ActiveMQ 5.11.0** source
and the condition is already covered by Apache's historical deserialization
remediation. It is therefore a duplicate / historical finding rather than a
reportable new vulnerability. This verdict does **not** assert that 5.11.0 was
safe; it rejects only the candidate's present vendor-reportability.

## Scope and revision integrity

- Repository: `https://github.com/apache/activemq.git`
- Requested commit: `4ba1a1689f33d81bd2349a2bb8c66f0c95b04d1d`
- Checked-out commit: `4ba1a1689f33d81bd2349a2bb8c66f0c95b04d1d`
- Local tag at that commit: `activemq-5.11.0`
- Working tree: clean at time of evidence capture.

The source receipt records SHA-256 hashes for each inspected source file.

## Technical findings

### 1. HTTP input reaches XStream before session validation

`HttpTunnelServlet.doPost` reads the HTTP request stream and passes it to
`wireFormat.unmarshalText(...)` at
`activemq-http/src/main/java/org/apache/activemq/transport/http/HttpTunnelServlet.java:120-127`.

Only after that operation does the non-`WireFormatInfo` path look up the
`clientID` session at lines `138-143`. The lookup itself is implemented at lines
`166-179`. Thus an invalid or absent `clientID` does not prevent XStream parsing
from occurring first.

The transport server creates the servlet in a Jetty context with
`ServletContextHandler.NO_SECURITY` at
`activemq-http/src/main/java/org/apache/activemq/transport/http/HttpTransportServer.java:83-88`.
This source establishes no HTTP-layer authentication gate in this implementation.
Broker authentication plugins, when configured, act on the decoded
`ConnectionInfo` command (`SimpleAuthenticationBroker.addConnection`,
`activemq-broker/src/main/java/org/apache/activemq/security/SimpleAuthenticationBroker.java:67-103`), which is later in the protocol path.

### 2. The pinned HTTP transport selects plain XStream without a type allowlist

- `HttpTransportFactory.getDefaultWireFormatType()` returns `"xstream"` at
  `activemq-http/src/main/java/org/apache/activemq/transport/http/HttpTransportFactory.java:64-66`.
- `HttpTransportServer.createWireFormat()` creates `new XStreamWireFormat()` at
  `activemq-http/src/main/java/org/apache/activemq/transport/http/HttpTransportServer.java:66-68`.
- `XStreamWireFormat.unmarshalText` invokes `getXStream().fromXML(...)` at
  `activemq-http/src/main/java/org/apache/activemq/transport/xstream/XStreamWireFormat.java:55-62`.
- Its pinned `createXStream()` implementation uses `new XStream()` and only calls
  `ignoreUnknownElements()` at lines `112-115`. There is no `NoTypePermission`,
  `allowTypes`, `allowTypesByWildcard`, or equivalent local restriction.
- The parent POM fixes the XStream dependency to version `1.4.7` at `pom.xml:128`
  and manages the dependency at `pom.xml:913-915`.

These facts confirm the candidate's core source-level premise for the pinned
release. No weaponized input was created or executed.

### 3. Exposure is not the standalone default, but requires an HTTP/HTTPS connector

The distributed `assembly/src/release/conf/activemq.xml:111-118` enables TCP,
AMQP, STOMP, MQTT, and WS connectors; it does not enable an HTTP or HTTPS
transport connector. Therefore HTTP transport is not exposed by the stock
standalone configuration.

The feature is nevertheless a normal, implemented transport: HTTP module tests
configure `http://localhost:8081` and related HTTP/HTTPS connectors. An affected
deployment needs an operator-provided HTTP/HTTPS connector and network reachability
to it. At the servlet itself, parsing precedes the `clientID` session lookup; a
separate deployment-level reverse proxy or external authentication layer could
change practical reachability, but is not present in this source path.

### 4. This is historical, known, and remediated

The checked repository contains later commit
`e7a4b53f799685e337972dd36ba0253c04bcc01f` (author date 2015-10-16), titled:

`AMQ-6013 - restrict classes which can be serialized inside the broker`

For this exact HTTP `XStreamWireFormat`, the change replaces `new XStream()` with
`XStreamSupport.createXStream()`. The resulting support code applies
`NoTypePermission.NONE`, permits primitives, collections, maps, strings, and then
only approved package wildcards (or an explicit all-allowed compatibility setting).
The remediating commit is contained in tags `activemq-5.12.2` and
`activemq-5.12.3`; the pinned version is `activemq-5.11.0`.

Apache's preserved advisory `CVE-2015-5254` states that ActiveMQ `5.0.0 - 5.12.1`
is affected by unsafe deserialization and recommends upgrading to 5.13.0. Its
description highlights `ObjectMessage` pathways, while the repository's AMQ-6013
fix directly shows that the HTTP XStream wire-format restriction was included in
the same historical remediation period. The candidate must therefore not be filed
as a newly discovered issue.

## Dynamic-harness boundary

A small local harness was considered, but this machine has no installed Java
runtime (`/usr/libexec/java_home -V` reports none) and no Maven executable. No
server was started and no payload was generated. This does not affect the
duplicate/historical finding determination because the checked source, explicit
post-fix diff, release tags, and Apache advisory supply independent evidence.

What remains unproven:

- Exact runtime behavior of a benign non-allowlisted XML type under the pinned
  dependency set, due to the absent JRE/Maven.
- The actual network exposure and any proxy authentication of a particular
  third-party 5.11.0 deployment; those are deployment-specific and unnecessary
  to establish that the candidate is a historical duplicate.

## Artifacts

- `activemq/` — detached local checkout at the requested revision.
- `evidence/source-receipt.txt` — numbered source excerpts, revision/tag facts,
  relevant file hashes, remediation diff, and runtime-tool probes.
- `evidence/CVE-2015-5254-announcement.txt` — downloaded Apache advisory text.
- `verification-report.md` — this conclusion.

## Recommendation

Close `apache_001` as **historical / duplicate, not vendor-reportable**. If the
audit needs a current issue, restrict new candidates to supported latest-HEAD or
current release revisions and de-duplicate against release tags, advisories, and
security-fix history before ranking.
