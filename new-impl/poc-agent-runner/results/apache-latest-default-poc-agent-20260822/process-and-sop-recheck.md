# Apache Latest-Default PoC Process And SOP Recheck

Updated: 2026-08-23

This document records the detailed process behind the first five
latest/default Apache PoC-agent reviews. It uses the runtime PoC validation SOP
as a review aid, not as a fixed output schema.

Raw TraeX event streams, prompts, local source checkouts, full logs, absolute
local paths, and credentials are intentionally excluded from this committed
snapshot. Short source excerpts and sanitized PoC markers are retained so a
reviewer can understand what was tested and what remains uncertain.

## ActiveMQ Process Record

### 1. Candidate Intake And Hypothesis Narrowing

- Case: `apache_master_001`
- Repository: `apache__activemq`
- Finding ID: `csf_292e1f7d633ee069b3d50b68`
- Rule ID: `missing-auth.discovery-registry`
- Audited revision: `4c0d70250faed7e3739f7ef14f0d72f1625d42c1`
- Revision date recorded by the audit: `2026-08-20T14:45:01-05:00`

The initial scanner claim was broad: the HTTP discovery registry could be
mutated without authentication. The first useful split was to separate three
questions:

- whether unauthenticated HTTP clients can add and remove registry entries;
- whether a discovery client actually consumes those entries as broker
  endpoints;
- whether enabling the embedded registry creates a network-reachable writable
  control plane beyond the operator's expectation.

The first two questions are runtime-testable. The third question depends on
configuration and ActiveMQ's documented security model.

### 2. Source Review Before PoC

The source review found a small, direct mutation path in the servlet:

```java
protected void doPut(HttpServletRequest req, HttpServletResponse resp) {
    String group = req.getPathInfo();
    String service = req.getHeader("service");
    ConcurrentMap<String, Long> services = getServiceGroup(group);
    services.put(service, System.currentTimeMillis());
}

protected void doDelete(HttpServletRequest req, HttpServletResponse resp) {
    String group = req.getPathInfo();
    String service = req.getHeader("service");
    ConcurrentMap<String, Long> services = getServiceGroup(group);
    services.remove(service);
}
```

The discovery agent consumes registry output and turns new lines into discovery
events:

```java
Set<String> activeServices = doLookup(updateInterval * 3);
...
for (String service : addedServices) {
    SimpleDiscoveryEvent e = new SimpleDiscoveryEvent(service);
    discoveredServices.put(service, e);
    discoveryListener.onServiceAdd(e);
}
```

The embedded registry is optional, but when `startEmbeddRegistry` is true it is
started from the discovery agent:

```java
if (startEmbeddRegistry) {
    jetty = createEmbeddedJettyServer();
    props.put("agent", this);
    IntrospectionSupport.setProperties(jetty, props);
    jetty.start();
}
```

The listener-binding question came from `EmbeddedJettyServer`, which parses the
configured URL but constructs Jetty only from the port:

```java
URI uri = new URI(agent.getRegistryURL());
int port = 80;
if (uri.getPort() >= 0) {
    port = uri.getPort();
}
server = new Server(port);
```

This made the source-backed hypothesis sharper: the behavior is not about
default broker authentication; it is about an optional embedded HTTP registry
that accepts unauthenticated mutation and may listen more broadly than the URL
host suggests.

### 3. Runtime And PoC Construction

A focused Maven harness was used instead of a full broker deployment because the
affected behavior lives in `activemq-http` product code. The harness built from
the audited source revision, started `EmbeddedJettyServer`, issued HTTP
requests, and observed a victim `DiscoveryTransport` through ActiveMQ's test
transport support.

The first required runtime evidence was a simple state transition:

```text
baseline_sink_uris=[]
unauthenticated_put_status=200
registry_after_put=tcp://127.0.0.1:61666
sink_after_put=[tcp://127.0.0.1:61666]
unauthenticated_delete_status=200
registry_after_delete=
sink_after_delete=[]
RESULT=CONFIRMED
```

This confirmed the product-code behavior claimed by the scanner. It did not by
itself settle reportability, because registry mutation can overlap with
documented discovery trust assumptions.

### 4. Listener Exposure Check

After the basic PoC, the next question was whether a registry configured with a
`localhost` URL was actually limited to loopback. A hold harness configured the
embedded registry as `http://localhost:18080/discovery-registry/poc`, then
socket inspection and HTTP requests through the host LAN address showed the
service was not loopback-only in the tested environment.

This strengthened the operator-expectation angle: a configuration that visually
uses `localhost` may still create a listener reachable through another local
interface because `EmbeddedJettyServer` keeps only the port when constructing
Jetty.

The exposure test was cleaned up after the check; no long-running hold process
was intentionally kept.

### 5. Security-Model And Duplicate Review

The review then looked for official documentation, public advisories, issue
history, and adjacent CVEs before sending any report.

The most important official-documentation finding was ActiveMQ's discovery
security warning:

```text
When using auto discovery of brokers an attacker may be able to present itself
as a legitimate broker and by this way catch and / or manipulate all messages
that run over it.
```

This warning overlaps with broker-discovery poisoning. It weakens a report that
only says "an attacker can publish an endpoint." The potentially reportable
question becomes narrower:

- does `startEmbeddRegistry=true` intentionally create a writable unauthenticated
  HTTP registry for any reachable network client;
- does the `localhost` URL host being ignored violate operator expectation;
- is the documentation clear enough that this should be treated as an accepted
  trusted-network deployment property rather than a vulnerability.

Public search found adjacent HTTP-discovery history, but no public duplicate was
identified for this exact unauthenticated embedded-registry PUT/DELETE plus
listener-binding combination.

### 6. PoC Attachment Package

A portable PoC package was created outside the repository and attached to the
private Gmail draft. The package contains source and runner material only:

- `README.md`
- `pom.xml`
- `run-poc.sh`
- Java PoC source

The package intentionally excludes local build directories, raw agent event
streams, credentials, and local source checkouts. The confirmation log was kept
outside the zip as local evidence.

### 7. Disclosure Draft State

The Gmail draft was updated but not sent. The subject was adjusted to avoid
overclaiming default broker compromise:

```text
[SECURITY] ActiveMQ Classic embedded HTTP discovery registry allows unauthenticated mutation and may bind beyond localhost
```

The draft asks Apache Security whether the behavior is intended under the
ActiveMQ security model. That question matters because official documentation
already acknowledges risk around auto discovery.

### 8. Current ActiveMQ Interpretation

The runtime evidence is strong for unauthenticated registry mutation and
downstream discovery-client observation on the pinned revision. The security
classification is configuration- and model-dependent.

The strongest remaining report angle is not simply "discovery can be poisoned";
it is the combination of an optional embedded writable registry, no servlet-level
authentication or role check, and a listener construction path that may bind
beyond the configured URL host.

## SOP Recheck Of The Other Four Cases

### Artemis OpenWire Durable Subscription Delete

- Case: `apache_master_002`
- Repository: `apache__activemq-artemis`
- Finding ID: `csf_3d425881daa2c96bd9968a9d`
- Rule ID: `authorization-bypass.queue-delete`
- Audited revision: `a5f4979e2fe14997dcf2d5fa90cd27a6cd8f2050`
- Revision date: `2026-08-20T15:40:58-05:00`
- PoC-agent status: completed

Source review shows OpenWire subscription removal directly destroys a durable
subscription queue:

```java
public Response processRemoveSubscription(RemoveSubscriptionInfo subInfo)
        throws Exception {
    SimpleString subQueueName =
        ActiveMQDestination.createQueueNameForSubscription(
            true, subInfo.getClientId(), subInfo.getSubscriptionName());
    server.destroyQueue(subQueueName);
    return null;
}
```

The relevant server-side security check is conditional on having a non-null
session:

```java
if (session != null) {
    securityStore.check(address, queueName,
        queue.isDurable() ? CheckType.DELETE_DURABLE_QUEUE
                          : CheckType.DELETE_NON_DURABLE_QUEUE,
        session);
}
```

The PoC-agent used a real embedded Artemis broker with OpenWire and security
enabled. It first confirmed the same user was denied on the normal core delete
path for missing `DELETE_DURABLE_QUEUE`, then used OpenWire
`Session.unsubscribe("retainedOrders")` with the victim client ID and observed
the victim durable subscription queue deleted.

Sanitized final evidence:

```text
POC_BEFORE_UNSUB queue=victimClient.retainedOrders exists=true messageCount=1
POC_CONTROL core delete denied: missing DELETE_DURABLE_QUEUE
POC_CONFIRMED OpenWire RemoveSubscriptionInfo deleted victimClient.retainedOrders
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Issues encountered:

- initial Maven run needed local snapshot reactor artifacts;
- a later run was skipped until integration tests were explicitly enabled;
- one run hit a Java cleaner-thread leak check after the PoC body had passed;
- the final focused run completed cleanly.

SOP recheck result: this remains a high-signal authorization-boundary candidate.
The next useful review step is duplicate/advisory search and precise affected
release mapping before vendor reporting.

### Axis Latest/Default Candidate

- Case: `apache_master_003`
- Repository: `apache__axis-axis1-java`
- Audited revision: `2c0d66018480e0cb73d5005c99c68ef55558d2a3`
- Revision date: `2025-02-09T13:54:28-10:00`
- PoC-agent status: not run

The latest/default false-positive workflow has a freshness gate: current-project
PoC validation is reserved for repositories whose frozen latest/default commit
is dated in 2026. Axis did not pass that gate.

SOP recheck result: this case remains skipped for the current latest/default
new-project audit batch. Older Axis SOAP/DIME resource-exhaustion discussions
should stay separate from this gated batch unless the user explicitly opens a
historical-CVE or legacy-maintenance review track.

### Camel FTP/SFTP Remote Listing Path

- Case: `apache_master_004`
- Repository: `apache__camel`
- Finding ID: `csf_8a5accddbd0026c2a35dfc97`
- Rule ID: `path-traversal.remote-file`
- Audited revision: `ca11b8250b66722c69509ed5074ac5b6a6000141`
- Revision date: `2026-08-16T17:07:15+02:00`
- PoC-agent status: outer process token-limited after writing dynamic artifacts

Source review shows FTP listing names are joined into Camel's remote-file path:

```java
String absoluteFilePath = absoluteFilePath(absolutePath, file.getName());
...
answer.setFileNameOnly(file.getName());
answer.setAbsoluteFilePath(absoluteFilePath);
answer.setFileName(answer.getRelativeFilePath());
```

The path join itself does not enforce segment containment:

```java
String dir = FileUtil.stripTrailingSeparator(absolutePath);
String fileName = name;
String absoluteFileName = FileUtil.stripLeadingSeparator(dir + "/" + fileName);
```

The non-stepwise FTP sinks then pass the resulting path to Commons Net:

```java
result = client.retrieveFile(remoteName, bos);
...
result = client.deleteFile(target);
```

The dynamic artifact confirmed the behavior with a malicious FTP listing entry:

```text
LISTING_NAME_FROM_SERVER=a/../../../secret.txt
CAMEL_FTPUTILS_ABSOLUTE_PATH=poll/a/../../../secret.txt
COMMONS_NET_RETR_COMMAND=RETR poll/a/../../../secret.txt
COMMONS_NET_DELE_COMMAND=DELE poll/a/../../../secret.txt
SERVER_NORMALIZED_RETR_PATH=/secret.txt
SERVER_NORMALIZED_DELE_PATH=/secret.txt
RETRIEVED_BODY=SECRET_OUTSIDE_POLL_DIR
POC_VERDICT=CONFIRMED
```

Issues encountered:

- in-repo Maven/JUnit attempts were blocked by unrelated Camel reactor and
  project-extension behavior before reaching the `camel-ftp` test phase;
- the final standalone harness used source guards and Commons Net behavior to
  preserve the relevant product path;
- one standalone run lacked a Commons IO runtime dependency and was corrected.

SOP recheck result: the runtime behavior is confirmed by artifact, but vendor
reportability needs a careful security-model review. The relevant boundary is a
malicious or compromised FTP/SFTP server controlling listing names. A reviewer
should check whether Camel documents the remote server as fully trusted, whether
`stepwise=false`, `delete`, `move`, or streaming options change exposure, and
whether path-containment expectations exist for consumers.

### Cassandra ADD IDENTITY Target-Role Authorization

- Case: `apache_master_005`
- Repository: `apache__cassandra`
- Finding ID: `csf_9244df69ff5fc732087916e4`
- Rule ID: `authz.add-identity-target-role-control`
- Audited revision: `f8e301875d07b29ff840526fe03e5b4bd7567738`
- Revision date: `2026-08-19T20:14:33+02:00`
- PoC-agent status: completed

Source review shows `ADD IDENTITY` authorizes global role creation rather than
checking control of the target role:

```java
public void authorize(ClientState state) {
    checkPermission(state, Permission.CREATE, RoleResource.root());

    if (!state.getUser().isSuper()
            && DatabaseDescriptor.getRoleManager().isSuper(RoleResource.role(role)))
        throw new UnauthorizedException(...);
}
```

Execution then adds the mapping:

```java
DatabaseDescriptor.getRoleManager().addIdentity(identity, role);
```

The role manager stores the identity-to-role association:

```java
String query = String.format(
    "INSERT INTO %s.%s (identity, role) VALUES (?, ?)",
    SchemaConstants.AUTH_KEYSPACE_NAME,
    AuthKeyspace.IDENTITY_TO_ROLES);
process(query, CassandraAuthorizer.authWriteConsistencyLevel(),
        byteBuf(identity), byteBuf(role));
```

The mTLS authenticator consumes the mapping as the authenticated role:

```java
String role = identityCache.get(identity);
...
return new AuthenticatedUser(role, MTLS,
    Map.of(METADATA_IDENTITY_KEY, identity));
```

Sanitized dynamic evidence:

```text
POC_CONFIRMED: attacker=poc_attacker only_has_create_on_all_roles=true bound_identity=spiffe://testdomain.com/testIdentifier/testValue authenticated_as=poc_victim
```

The final JUnit XML recorded one test with zero errors and zero failures.

Issues encountered:

- local macOS execution did not have a viable Cassandra Java runtime;
- remote execution required a workspace-local Maven repository and exact
  checkout/submodule staging;
- initial remote attempts failed on missing helper classes, submodule fetch, and
  cache permissions before the clean run succeeded.

SOP recheck result: this remains a high-signal authorization-boundary candidate.
The central security question is whether `CREATE ON ALL ROLES` is intended to
permit binding arbitrary mTLS identities to unrelated non-superuser roles. If
not, the PoC demonstrates privilege delegation to a victim role without target
role control.

## Cross-Case Review Notes

| Case | Runtime evidence | Main remaining question |
| --- | --- | --- |
| ActiveMQ | Confirmed unauthenticated mutation and downstream discovery observation | Whether the embedded writable registry and broad binding violate documented deployment expectations |
| Artemis | Confirmed OpenWire path bypasses queue-delete authorization enforced by the control path | Duplicate/advisory search and affected release mapping |
| Axis | Not run due to non-2026 latest/default revision | Separate only if a historical/legacy review track is opened |
| Camel | Confirmed by dynamic artifact despite outer token-limit termination | Whether a malicious remote FTP/SFTP server is inside or outside Camel's intended trust boundary |
| Cassandra | Confirmed target-role mapping by a role creator without victim-role control | Whether Cassandra intends `CREATE ON ALL ROLES` to grant arbitrary identity binding to non-superuser roles |

## Follow-Up Queue

- Keep the ActiveMQ draft unsent until final human review of the security-model
  framing.
- For Artemis and Cassandra, run duplicate/advisory checks and prepare concise
  vendor-facing drafts if no duplicate is found.
- For Camel, prioritize security-model review before drafting because the
  attacker is the remote file server.
- Keep Axis out of this latest/default 2026-gated batch unless the workflow
  changes.
