---
name: arthas-instrument
description: Use this skill when the user asks to hook, trace, watch, or diagnose Java methods at runtime using Arthas inside a Docker container. Also use when Frida is unavailable (JDK 8), or when the user asks to watch method params/return values, trace call trees, or decompile classes at runtime.
allowed-tools: [Bash, Read, Write]
---

# Arthas Instrument

## Two Modes

| Mode | Tool | When to Use |
|------|------|-------------|
| **Interactive** | `arthas-boot.jar` | Exploration, debugging, one-off queries |
| **Non-interactive** | `arthas-client.jar` | Scripts, automation, batch verification |

## Non-Interactive Mode (PREFERRED for scripts)

Many target images already have Arthas pre-installed at `/root/.arthas/`. Check first:

```bash
docker exec <container> ls /root/.arthas/lib/4.2.0/arthas/arthas-client.jar
```

### Execution pattern

```bash
JH=/usr/lib/jvm/temurin-17-jdk-amd64
AH=/root/.arthas/lib/4.2.0/arthas/arthas-client.jar

# Single command:
docker exec -e http_proxy= -e https_proxy= <container> sh -c \
  "timeout 30 $JH/bin/java -jar $AH 127.0.0.1 3658 -c '<command>' 2>&1"

# Commands:
#   reset                      — clear all watches/listeners
#   watch Class method ...     — set watchpoint
#   tt -t Class method -n 10   — time-tunnel recording
#   tt -l                      — list recordings
#   jad Class                  — decompile
```

**CRITICAL**: Always unset `http_proxy`/`https_proxy` when Arthas connects to `127.0.0.1:3658`. Proxy env vars cause connection failures.

### Shell escaping for OGNL (IMPORTANT)

`{`, `}`, `(`, `)`, `#` in OGNL expressions WILL break bash strings. Solutions, in order of preference:

1. **Simple expressions without braces**: `instances[0].field` not `{field: instances[0].field}`
2. **File-based commands**: Write commands to `/tmp/cmds.txt` inside container, then use Arthas `-f /tmp/cmds.txt` (if supported by your arthas-client.jar version)
3. **Single quotes for watch expressions**: `watch Class method '{params,returnObj}' -x 2` — the outer double-quotes in bash protect the single-quoted OGNL

### Background watch with output redirection

For long-running watches that capture output while your script does other things:

```bash
docker exec -d -e http_proxy= -e https_proxy= <container> sh -c "
    timeout 120 $JH/bin/java -jar $AH 127.0.0.1 3658 -c '
        watch com.example.Class method \
            \"{params,returnObj}\" -x 3 -n 20' \
    > /tmp/watch_output.txt 2>&1
"
```

Then check results:
```bash
docker exec <container> cat /tmp/watch_output.txt
```

### Python helper function

```python
import subprocess, os, re

def arthas(cmd, timeout=25):
    """Execute Arthas command non-interactively inside container."""
    env = os.environ.copy()
    env.pop('http_proxy', None); env.pop('https_proxy', None)
    r = subprocess.run(
        ["docker", "exec", "-e", "http_proxy=", "-e", "https_proxy=", CID, "sh", "-c",
         f"timeout {timeout} {JH}/bin/java -jar {AH} 127.0.0.1 3658 -c '{cmd}' 2>&1"],
        capture_output=True, text=True, timeout=timeout+15, env=env)
    return re.sub(r'\x1b\[[0-9;]*m', '', r.stdout + r.stderr)
```

## Interactive Mode (exploration)

### Step 1 — Start the container

```bash
route-hacker instrument shell <image> --keep
# Add --port 8080:8080 if the app needs a port mapped
```

Note the container ID. All subsequent steps reference `<container>`.

### Step 2 — Download arthas-boot.jar

```bash
curl -sL -o /tmp/arthas-boot.jar https://arthas.aliyun.com/arthas-boot.jar
docker cp /tmp/arthas-boot.jar <container>:/tmp/
```

### Step 3 — Start the Java application

Inside the container shell, start the app normally:

```bash
docker exec -it <container> bash
# then: java -jar app.jar  or  java -cp ... MainClass  etc.
```

### Step 4 — Attach Arthas

In a second terminal:

```bash
# Interactive — Arthas lists running JVMs, pick by number:
docker exec -it <container> java -jar /tmp/arthas-boot.jar

# Direct attach by PID (use jps -l to find it):
docker exec -it <container> java -jar /tmp/arthas-boot.jar <PID>

# Non-interactive one-shot:
docker exec -it <container> java -jar /tmp/arthas-boot.jar <PID> -c 'watch ...'
```

## Command Reference

### Watch (capture params, return, exceptions)

```
watch com.example.Controller.processRequest '{params, returnObj, throwExp}' -x 3
watch com.example.Service.query '{params, returnObj}' 'params[0].contains("admin")' -x 3
```
`-x 3` = expand depth 3, `-n 10` = max 10 hits.

### Time-Tunnel (record invocations, list later)

```
tt -t com.example.Service.lookup -n 10     # record up to 10 invocations
tt -l                                       # list all recordings
tt -i 1000 -w '{params, returnObj}' -x 2   # inspect recording index 1000
```
**Prefer `tt` over `watch` for scripted verification.** Recordings persist and can be checked after the fact — no timing issues with output capture.

### Trace / Stack

```
trace com.example.Controller.processRequest
stack com.example.Service.dangerousOperation
```

### Decompile / Search

```
jad com.example.Controller          # decompile (needs JDK, not just JRE)
sc *Controller*                     # search classes
sm com.example.Service *            # search methods
```

### Thread / Memory / OGNL

```
thread -n 5                         # busiest 5 threads
vmtool --action getInstances --className com.example.Class \
  --express 'instances[0].field.enabled' -x 1
vmtool --action forceGc
ognl '@com.example.Config@getValue("key")'
```

## Verification Workflow (scripted)

```
1. arthas("reset")                                    # clean slate
2. arthas("tt -t com.example.VulnClass vulnMethod -n 10")   # set recording
3. [send HTTP request to trigger vulnerability]
4. time.sleep(3)
5. arthas("tt -l")                                    # check recordings
   → "Affect(row-cnt:N)" where N>0 means CONFIRMED
```

## Notes

- `jad` requires a JDK, not just a JRE.
- Use `jps -l` inside the container if Arthas doesn't auto-discover the JVM.
- arthas-boot.jar is ~140 KB — fast to download and copy.
- Arthas listens on `127.0.0.1:3658` by default after first attach.
- For non-interactive mode, Arthas must already be attached to the JVM. The app container typically has Arthas pre-attached.
