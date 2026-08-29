---
name: frida-instrument
description: Use this skill when the user asks to hook, trace, or intercept Java methods at runtime using Frida inside a Docker container. Also use when the user asks to instrument a Java app with Frida, attach Frida to a JVM, or load a Frida hook script.
allowed-tools: [Bash, Read, Write]
---

# Frida Instrument

## Step 0 — Check JDK compatibility first

Before doing anything, determine the JDK version inside the target image:

```bash
docker run --rm <image> java -version 2>&1 | head -1
```

| JDK | Action |
|-----|--------|
| 8 (Temurin) | **Stop. Use the `arthas-instrument` skill instead.** Frida Java Bridge is broken on JDK 8 — `libjvm.so` is missing `_ZN6Method10jmethod_idEv`. |
| 17 (Temurin) | Proceed below. |
| 21+ | Untested — try Arthas first. |

## Step 1 — Start the container

```bash
gca instrument shell <image> --keep
# Add --port 8080:8080 if the app needs a port mapped
```

Note the container ID. All subsequent steps reference `<container>`.

## Step 2 — Deploy frida-server

Check the installed frida version first — server and client must match:

```bash
pip show frida | grep Version
```

Download and copy (replace `17.9.10` with the actual version):

```bash
curl -fsSL -o /tmp/frida-server.xz \
  "https://github.com/frida/frida/releases/download/17.9.10/frida-server-17.9.10-linux-x86_64.xz"
xz -d /tmp/frida-server.xz
chmod +x /tmp/frida-server
docker cp /tmp/frida-server <container>:/tmp/frida-server
docker exec -d <container> /tmp/frida-server -l 0.0.0.0:27042
```

## Step 3 — Copy the Java bridge

The pre-compiled bundle is at `.claude/skills/frida-instrument/assets/java-bridge-loader.js`:

```bash
docker cp .claude/skills/frida-instrument/assets/java-bridge-loader.js <container>:/tmp/bridge.js
```

## Step 4 — Write the hook script

Create `/tmp/hook.js` with the target method. Template:

```javascript
globalThis.__runHooks = function(Java) {
    Java.perform(function() {
        var Target = Java.use('com.example.MyClass');

        // No-arg method:
        Target.methodName.overload().implementation = function() {
            console.log('[HOOK] methodName() called');
            send({hook: 'methodName', args: []});
            return this.methodName();
        };

        // Method with parameters:
        // Target.methodName.overload('java.lang.String', 'int').implementation = function(p1, p2) {
        //     console.log('[HOOK] methodName("' + p1 + '", ' + p2 + ')');
        //     send({hook: 'methodName', args: [p1, p2]});
        //     var result = this.methodName(p1, p2);
        //     console.log('[HOOK]   -> ' + result);
        //     return result;
        // };
    });
};
```

Concatenate hook with bridge, then copy into container:

```bash
cat /tmp/hook.js /tmp/bridge.js > /tmp/full.js
docker cp /tmp/full.js <container>:/tmp/full.js
```

## Step 5 — Attach Frida

```bash
# Find JVM PID inside container
docker exec <container> jps -l

# Get container IP
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' <container>

# Attach (needs frida-tools: pip install frida-tools)
frida -H <ip>:27042 -p <jvm_pid> -l /tmp/full.js
```

## Step 6 — Trigger and observe

Send HTTP requests to exercise the hooked code path. Frida prints `[HOOK]` lines and `send()` payloads in real time.

## When to use Arthas instead

| Scenario | Use |
|----------|-----|
| JDK 8 | Arthas |
| Quick watch/trace, no JS needed | Arthas |
| Call tree / record-replay (`tt`) | Arthas |
| Complex JS logic, conditional hooks | Frida |
| JDK 17+, need JS `send()` payloads | Frida |
