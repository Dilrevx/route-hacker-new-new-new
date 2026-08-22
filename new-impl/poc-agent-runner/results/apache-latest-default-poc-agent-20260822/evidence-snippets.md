# Evidence Snippets

This file keeps only short, sanitized evidence markers from the local
PoC-agent artifacts. It excludes raw event streams, prompts, local source
checkouts, full runtime logs, and credentials.

## ActiveMQ Discovery Registry

- Case: `apache_master_001`
- Finding: `csf_292e1f7d633ee069b3d50b68`
- Revision: `4c0d70250faed7e3739f7ef14f0d72f1625d42c1`
- Verdict: `CONFIRMED`

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

## Artemis OpenWire Durable Subscription Delete

- Case: `apache_master_002`
- Finding: `csf_3d425881daa2c96bd9968a9d`
- Revision: `a5f4979e2fe14997dcf2d5fa90cd27a6cd8f2050`
- Verdict: `CONFIRMED`

```text
POC_BEFORE_UNSUB queue=victimClient.retainedOrders exists=true messageCount=1
POC_CONTROL core delete denied: AMQ229213: User: pocAttacker does not have permission='DELETE_DURABLE_QUEUE' for queue victimClient.retainedOrders on address poc.topic
POC_CONFIRMED OpenWire RemoveSubscriptionInfo deleted victimClient.retainedOrders as pocAttacker without DELETE_DURABLE_QUEUE
Tests run: 1, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

## Axis Revision Gate

- Case: `apache_master_003`
- Revision: `2c0d66018480e0cb73d5005c99c68ef55558d2a3`
- Default branch commit date: `2025-02-09T13:54:28-10:00`
- Verdict: `SKIPPED_REVISION_GATE`

Axis was not sent to PoC-agent in this latest-default false-positive audit
round because its frozen latest/default branch commit is not dated in 2026.

## Camel FTP Remote Listing Path

- Case: `apache_master_004`
- Finding: `csf_8a5accddbd0026c2a35dfc97`
- Revision: `ca11b8250b66722c69509ed5074ac5b6a6000141`
- Verdict: `CONFIRMED_BY_DYNAMIC_ARTIFACT`
- Boundary: the dynamic artifact and receipt confirmed the behavior, but the
  outer PoC-agent process exceeded its token limit before writing a normal final
  message.

```text
TARGET_COMMIT=ca11b8250b66722c69509ed5074ac5b6a6000141
TARGET_SOURCE_GUARDS=OK
LISTING_NAME_FROM_SERVER=a/../../../secret.txt
CAMEL_FTPUTILS_ABSOLUTE_PATH=poll/a/../../../secret.txt
COMMONS_NET_RETR_COMMAND=RETR poll/a/../../../secret.txt
COMMONS_NET_DELE_COMMAND=DELE poll/a/../../../secret.txt
SERVER_NORMALIZED_RETR_PATH=/secret.txt
SERVER_NORMALIZED_DELE_PATH=/secret.txt
RETRIEVED_BODY=SECRET_OUTSIDE_POLL_DIR
POC_VERDICT=CONFIRMED
```

## Cassandra ADD IDENTITY Target-Role Authorization

- Case: `apache_master_005`
- Finding: `csf_9244df69ff5fc732087916e4`
- Revision: `f8e301875d07b29ff840526fe03e5b4bd7567738`
- Verdict: `CONFIRMED`

```text
POC_CONFIRMED: attacker=poc_attacker only_has_create_on_all_roles=true bound_identity=spiffe://testdomain.com/testIdentifier/testValue authenticated_as=poc_victim
```

Final clean JUnit run:

```xml
<testsuite errors="0" failures="0" hostname="ubun" name="org.apache.cassandra.auth.AddIdentityTargetRoleAuthzPoCTest-_jdk11" skipped="0" tests="1" time="4.249" timestamp="2026-08-22T14:18:09">
  <testcase classname="org.apache.cassandra.auth.AddIdentityTargetRoleAuthzPoCTest" name="delegatedRoleCreatorCanBindMtlsIdentityToUncontrolledVictimRole-_jdk11" time="0.749" />
</testsuite>
```
