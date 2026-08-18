# Codex Security Critical Findings PoC Validation Summary

Generated: 2026-08-17T23:25:54+00:00
Run root: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z`

## Verdict Counts

- `CONFIRMED`: 11
- `REJECTED`: 2

## Findings

| # | Verdict | Case | Repo | CVE | Finding | Rule | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | `CONFIRMED` | case_009 | apache__activemq | CVE-2014-3576 | `csf_0f2e09e5c3317bfbd771e485` | `java.xstream.stomp-transformation-deserialization` | CWE-502 is dynamically demonstrated: untrusted STOMP XML reaches unrestricted XStream deserialization and can execute attacker-controlled invocation logic. The harness modifies ... |
| 2 | `CONFIRMED` | case_009 | apache__activemq | CVE-2014-3576 | `csf_64779d6cccce4eb8328ae0c0` | `web.fileserver.unauthenticated-arbitrary-file-write` | The fileserver web.xml leaves RestFilter write-permission-role unset. RestFilter therefore permits unauthenticated PUT, MOVE, and DELETE. Its MOVE handler trusts the Destination... |
| 3 | `CONFIRMED` | case_010 | apache__activemq | CVE-2020-11998 | `csf_9a500c80d16b1d82e4d630a3` | `deserialization.openwire.throwable-class-instantiation` | Confirmed on a faithful network harness using the exact vulnerable source checkout and its locally built activemq-all-5.15.12.jar. The originally named runtime image had been pr... |
| 4 | `CONFIRMED` | case_016 | apache__commons-text | CVE-2022-42889 | `csf_bba673819bc9682cd890b837` | `code-injection.default-interpolator-script` | The prepared image tag was absent, so validation used the preserved exact Commons Text 1.9 JAR, Commons Lang dependency, compiled endpoint, and endpoint source from the runtime ... |
| 5 | `CONFIRMED` | case_018 | apache__felix-dev | CVE-2025-25247 | `csf_db9638924c805482bc2ebdea` | `default-credentials.management-console` | The target's protected management-console bundles endpoint challenges requests without credentials and with deliberately invalid credentials (both HTTP 401), then grants HTTP 20... |
| 6 | `CONFIRMED` | case_020 | apache__inlong | CVE-2025-27531 | `csf_1673a9a5a8937ab9ac0677df` | `authentication.openapi-default-admin` | The runtime configuration has openapi.auth.enabled=false. The executable proof demonstrates an anonymous caller performing state-changing tenant creation that the application at... |
| 7 | `REJECTED` | case_020 | apache__inlong | CVE-2025-27531 | `csf_6635096ea0a669db757e59e6` | `authorization.module-lifecycle-command` | The reported security effect requires an unauthorized party to store a lifecycle command that an agent executes. The prepared vulnerable runtime returned HTTP 403 for the comple... |
| 8 | `CONFIRMED` | case_022 | apache__iotdb | CVE-2025-26864 | `csf_3accd0683d0328e8b3502bd6` | `iotdb-legacy-sync-public-superuser-mutation` | The supplied vulnerable IoTDB 1.3.3 image accepts unauthenticated legacy-sync handshakes and auto-registers the attacker-chosen database through a superuser session, yielding a ... |
| 9 | `CONFIRMED` | case_022 | apache__iotdb | CVE-2025-26864 | `csf_009fb93e6dbac6d9c4af05ee` | `iotdb-pipe-transfer-confignode-admin-impersonation` | The public DataNode client RPC Pipe endpoint forwarded an unauthenticated ConfigNode Pipe request and executed a privileged database-creation plan. This demonstrates the reporte... |
| 10 | `CONFIRMED` | case_040 | chartbrew__chartbrew | CVE-2026-32252 | `csf_1011bb63c96314324bb32853` | `authorization-bypass.data-request-scope` | DataRequestRoute authorizes membership for the URL team_id but does not verify that the routed dataset_id or data-request id belongs to that team. This allows a member of one te... |
| 11 | `CONFIRMED` | case_044 | conductor-oss__conductor | CVE-2025-26074 | `csf_ae40ddb293847bcdafcd58cb` | `unsandboxed-script-execution.workflow-definition` | The vulnerable server image built from the preserved runtime JAR executes caller-supplied INLINE JavaScript with Nashorn Java interoperation enabled; this is the exact capabilit... |
| 12 | `REJECTED` | case_045 | corewcf__corewcf | CVE-2026-54778 | `csf_169784d9e1d69ffeee602969` | `improper-signature-verification.ws-security-primary` | The claimed effect is not dynamically reproducible: a tampered primary WS-Security SignatureValue is rejected before the protected service operation is invoked. The static repor... |
| 13 | `CONFIRMED` | case_057 | ethyca__fides | CVE-2026-42303 | `csf_f85d4f81e47f9bb74317f6fe` | `broken-access-control.oauth-client-secret-rotation` | The vulnerable endpoint authorizes the operation solely with the global client:update scope. A separate attacker OAuth client with that single scope successfully called POST /ap... |

## Reproduction Commands

### 1. 01-case_009-apache__activemq-CVE-2014-3576-csf_0f2e09e5c3317bfbd771e485

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/01-case_009-apache__activemq-CVE-2014-3576-csf_0f2e09e5c3317bfbd771e485/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/01-case_009-apache__activemq-CVE-2014-3576-csf_0f2e09e5c3317bfbd771e485`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/01-case_009-apache__activemq-CVE-2014-3576-csf_0f2e09e5c3317bfbd771e485 && ./reproduce-instrumented.sh
```

### 2. 02-case_009-apache__activemq-CVE-2014-3576-csf_64779d6cccce4eb8328ae0c0

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/02-case_009-apache__activemq-CVE-2014-3576-csf_64779d6cccce4eb8328ae0c0/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/02-case_009-apache__activemq-CVE-2014-3576-csf_64779d6cccce4eb8328ae0c0/reproduce.sh`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/02-case_009-apache__activemq-CVE-2014-3576-csf_64779d6cccce4eb8328ae0c0 && ./reproduce.sh
```

### 3. 03-case_010-apache__activemq-CVE-2020-11998-csf_9a500c80d16b1d82e4d630a3

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/03-case_010-apache__activemq-CVE-2020-11998-csf_9a500c80d16b1d82e4d630a3/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/03-case_010-apache__activemq-CVE-2020-11998-csf_9a500c80d16b1d82e4d630a3`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/03-case_010-apache__activemq-CVE-2020-11998-csf_9a500c80d16b1d82e4d630a3 && ./reproduce.sh
```

### 4. 04-case_016-apache__commons-text-CVE-2022-42889-csf_bba673819bc9682cd890b837

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/04-case_016-apache__commons-text-CVE-2022-42889-csf_bba673819bc9682cd890b837/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/04-case_016-apache__commons-text-CVE-2022-42889-csf_bba673819bc9682cd890b837`

```bash
./reproduce_http.sh
```

### 5. 05-case_018-apache__felix-dev-CVE-2025-25247-csf_db9638924c805482bc2ebdea

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/05-case_018-apache__felix-dev-CVE-2025-25247-csf_db9638924c805482bc2ebdea/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/05-case_018-apache__felix-dev-CVE-2025-25247-csf_db9638924c805482bc2ebdea/reproduce.sh`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/05-case_018-apache__felix-dev-CVE-2025-25247-csf_db9638924c805482bc2ebdea && ./reproduce.sh
```

### 6. 06-case_020-apache__inlong-CVE-2025-27531-csf_1673a9a5a8937ab9ac0677df

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/06-case_020-apache__inlong-CVE-2025-27531-csf_1673a9a5a8937ab9ac0677df/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/06-case_020-apache__inlong-CVE-2025-27531-csf_1673a9a5a8937ab9ac0677df/reproduce.sh`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/06-case_020-apache__inlong-CVE-2025-27531-csf_1673a9a5a8937ab9ac0677df && mkdir -p evidence && ./reproduce.sh http://127.0.0.1:18195/inlong/manager | tee evidence/final-run.log
```

### 7. 07-case_020-apache__inlong-CVE-2025-27531-csf_6635096ea0a669db757e59e6

- Verdict: `REJECTED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/07-case_020-apache__inlong-CVE-2025-27531-csf_6635096ea0a669db757e59e6/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/07-case_020-apache__inlong-CVE-2025-27531-csf_6635096ea0a669db757e59e6`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/07-case_020-apache__inlong-CVE-2025-27531-csf_6635096ea0a669db757e59e6 && ./reproduce.sh
```

### 8. 08-case_022-apache__iotdb-CVE-2025-26864-csf_3accd0683d0328e8b3502bd6

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/08-case_022-apache__iotdb-CVE-2025-26864-csf_3accd0683d0328e8b3502bd6/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/08-case_022-apache__iotdb-CVE-2025-26864-csf_3accd0683d0328e8b3502bd6`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/08-case_022-apache__iotdb-CVE-2025-26864-csf_3accd0683d0328e8b3502bd6 && ./reproduce.sh
```

### 9. 09-case_022-apache__iotdb-CVE-2025-26864-csf_009fb93e6dbac6d9c4af05ee

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/09-case_022-apache__iotdb-CVE-2025-26864-csf_009fb93e6dbac6d9c4af05ee/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/09-case_022-apache__iotdb-CVE-2025-26864-csf_009fb93e6dbac6d9c4af05ee/PipeTransferUnauthenticated.java`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/09-case_022-apache__iotdb-CVE-2025-26864-csf_009fb93e6dbac6d9c4af05ee && ./reproduce.sh
```

### 10. 10-case_040-chartbrew__chartbrew-CVE-2026-32252-csf_1011bb63c96314324bb32853

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/10-case_040-chartbrew__chartbrew-CVE-2026-32252-csf_1011bb63c96314324bb32853/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/10-case_040-chartbrew__chartbrew-CVE-2026-32252-csf_1011bb63c96314324bb32853`

```bash
ssh bobo5090 'cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/10-case_040-chartbrew__chartbrew-CVE-2026-32252-csf_1011bb63c96314324bb32853 && ./reproduce.sh'
```

### 11. 11-case_044-conductor-oss__conductor-CVE-2025-26074-csf_ae40ddb293847bcdafcd58cb

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/11-case_044-conductor-oss__conductor-CVE-2025-26074-csf_ae40ddb293847bcdafcd58cb/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/11-case_044-conductor-oss__conductor-CVE-2025-26074-csf_ae40ddb293847bcdafcd58cb`

```bash
/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/11-case_044-conductor-oss__conductor-CVE-2025-26074-csf_ae40ddb293847bcdafcd58cb/reproduce.sh
```

### 12. 12-case_045-corewcf__corewcf-CVE-2026-54778-csf_169784d9e1d69ffeee602969

- Verdict: `REJECTED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/12-case_045-corewcf__corewcf-CVE-2026-54778-csf_169784d9e1d69ffeee602969/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/12-case_045-corewcf__corewcf-CVE-2026-54778-csf_169784d9e1d69ffeee602969`

```bash
cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/12-case_045-corewcf__corewcf-CVE-2026-54778-csf_169784d9e1d69ffeee602969 && ./reproduce.sh
```

### 13. 13-case_057-ethyca__fides-CVE-2026-42303-csf_f85d4f81e47f9bb74317f6fe

- Verdict: `CONFIRMED`
- Result: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/13-case_057-ethyca__fides-CVE-2026-42303-csf_f85d4f81e47f9bb74317f6fe/poc-result.json`
- Artifact: `/mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/13-case_057-ethyca__fides-CVE-2026-42303-csf_f85d4f81e47f9bb74317f6fe`

```bash
ssh bobo5090 'cd /mnt/dce94ca0-0dcc-412e-b434-f83bb74b35a7/lhq-runtime-v2/poc-agent-critical-findings-20260818T0615Z/poc-workspaces/13-case_057-ethyca__fides-CVE-2026-42303-csf_f85d4f81e47f9bb74317f6fe && ./reproduce.sh'
```

