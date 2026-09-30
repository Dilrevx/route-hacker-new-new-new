#!/usr/bin/env python3
import hashlib
import json
import os
import shutil
import socket
import subprocess
import tarfile
import threading
import time
from pathlib import Path


WORK = Path("/data/lhq/workspace/source-runtime-verify/apache_nifi_stateless__CVE-2021-42550__source_inserted")
CORE_SAMPLE = Path("/data/lhq/workspace/ljl-v1-core/source-insertion/samples/apache_nifi_stateless__CVE-2021-42550__source_inserted")
SOURCE_REPO = Path("/data/lhq/workspace/ljl-patch-java30-projects/repos/apache__nifi")
BASE_COMMIT = "fcbf1d5f975dd984e34f3a543b9480c779b0dc2f"
DIST_TGZ = Path("/data/lhq/workspace/ljl-strict-redo/historical-scan/nifi-stateless-1.14.0-bin.tar.gz")
DIST_DIR_NAME = "nifi-stateless-1.14.0"


def run(cmd, cwd=None, env=None, timeout=120, check=False):
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"command failed rc={proc.returncode}: {cmd}\nSTDOUT:\n{proc.stdout[-2000:]}\nSTDERR:\n{proc.stderr[-2000:]}")
    return proc


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class TcpHitCounter:
    def __init__(self):
        self.hits = []
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(20)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                pass
        except OSError:
            pass
        self._thread.join(timeout=2)
        self._sock.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    conn.settimeout(0.5)
                    data = conn.recv(64)
                except OSError:
                    data = b""
                if not self._stop.is_set():
                    self.hits.append({"addr": addr[0], "port": addr[1], "first_bytes_hex": data.hex()})


def prepare_source():
    src = WORK / "source"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)

    # Fetch only the files touched by this sample. The local NiFi cache can be
    # slow to archive under load; raw files at the exact base commit are enough
    # for this resource-level source insertion check.
    wanted = [
        "pom.xml",
        "nifi-stateless/nifi-stateless-resources/src/main/resources/bin/nifi-stateless.sh",
        "nifi-stateless/nifi-stateless-resources/src/main/resources/conf/stateless-logback.xml",
    ]
    for rel in wanted:
        out = src / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        url = f"https://raw.githubusercontent.com/apache/nifi/{BASE_COMMIT}/{rel}"
        res = run(["curl", "-fsSL", url, "-o", str(out)], timeout=120)
        if res.returncode != 0:
            raise RuntimeError(f"failed to fetch {url}\n{res.stderr[-1000:]}")

    patch = CORE_SAMPLE / "patch.diff"
    apply_check = run(["git", "apply", "--check", str(patch)], cwd=src, timeout=60)
    (WORK / "evidence").mkdir(parents=True, exist_ok=True)
    (WORK / "evidence" / "git-apply-check.rc").write_text(str(apply_check.returncode) + "\n")
    (WORK / "evidence" / "git-apply-check.stdout").write_text(apply_check.stdout)
    (WORK / "evidence" / "git-apply-check.stderr").write_text(apply_check.stderr)
    if apply_check.returncode != 0:
        raise RuntimeError(apply_check.stderr)
    run(["git", "apply", str(patch)], cwd=src, timeout=60, check=True)
    return src


def resolve_logback_jars():
    coords = [
        ("logback-core", "https://repo1.maven.org/maven2/ch/qos/logback/logback-core/1.2.7/logback-core-1.2.7.jar"),
        ("logback-classic", "https://repo1.maven.org/maven2/ch/qos/logback/logback-classic/1.2.7/logback-classic-1.2.7.jar"),
    ]
    deps = WORK / "deps"
    deps.mkdir(parents=True, exist_ok=True)
    found = {}
    for name, url in coords:
        jar = deps / f"{name}-1.2.7.jar"
        if not jar.exists():
            rc = run(["curl", "-fsSL", url, "-o", str(jar)], timeout=120)
            if rc.returncode != 0:
                raise RuntimeError(f"failed to download {url}\n{rc.stderr[-2000:]}")
        if not jar.exists():
            raise FileNotFoundError(jar)
        found[name] = jar
    return found


def prepare_runtime(src, logback_jars):
    runtime_root = WORK / "runtime-source"
    if runtime_root.exists():
        shutil.rmtree(runtime_root)
    runtime_root.mkdir(parents=True)
    with tarfile.open(DIST_TGZ) as tf:
        tf.extractall(runtime_root)
    dist = runtime_root / DIST_DIR_NAME

    source_bin = src / "nifi-stateless/nifi-stateless-resources/src/main/resources/bin/nifi-stateless.sh"
    source_conf = src / "nifi-stateless/nifi-stateless-resources/src/main/resources/conf/stateless-logback.xml"
    runtime_bin = dist / "bin/nifi-stateless.sh"
    runtime_conf = dist / "conf/stateless-logback.xml"

    before = {
        "runtime_bin_before_sha256": sha256(runtime_bin),
        "runtime_conf_before_sha256": sha256(runtime_conf),
    }
    shutil.copy2(source_bin, runtime_bin)
    shutil.copy2(source_conf, runtime_conf)
    os.chmod(runtime_bin, 0o755)

    lib = dist / "lib"
    for old in lib.glob("logback-*-1.2.3.jar"):
        old.unlink()
    for jar in logback_jars.values():
        shutil.copy2(jar, lib / jar.name)

    after = {
        "source_bin_sha256": sha256(source_bin),
        "source_conf_sha256": sha256(source_conf),
        "runtime_bin_after_sha256": sha256(runtime_bin),
        "runtime_conf_after_sha256": sha256(runtime_conf),
        "logback_core_1_2_7_sha256": sha256(logback_jars["logback-core"]),
        "logback_classic_1_2_7_sha256": sha256(logback_jars["logback-classic"]),
    }
    return dist, before | after


def run_case(dist, name, jndi_value):
    case_dir = WORK / "runs" / name
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)
    env = os.environ.copy()
    env.update(
        {
            "JAVA_HOME": env.get("JAVA_HOME", ""),
            "STATELESS_REVIEW_JNDI_LOCATION": jndi_value,
            "STATELESS_JAVA_OPTS": "-Xms64m -Xmx128m",
        }
    )
    start = time.time()
    proc = run(["bash", "bin/nifi-stateless.sh", "--help"], cwd=dist, env=env, timeout=35)
    elapsed = time.time() - start
    (case_dir / "stdout.txt").write_text(proc.stdout)
    (case_dir / "stderr.txt").write_text(proc.stderr)
    (case_dir / "rc.txt").write_text(str(proc.returncode) + "\n")
    return {
        "name": name,
        "jndi_value": jndi_value,
        "returncode": proc.returncode,
        "elapsed_seconds": round(elapsed, 3),
        "stdout_tail": proc.stdout[-3000:],
        "stderr_tail": proc.stderr[-5000:],
    }


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    (WORK / "evidence").mkdir(parents=True, exist_ok=True)
    src = prepare_source()
    logback_jars = resolve_logback_jars()
    dist, assembly = prepare_runtime(src, logback_jars)

    with TcpHitCounter() as listener:
        positive_value = f"rmi://127.0.0.1:{listener.port}/nifiStatelessReview"
        positive = run_case(dist, "positive", positive_value)
        time.sleep(1.0)
        positive_hits = list(listener.hits)

    with TcpHitCounter() as listener:
        negative_value = "java:comp/env/jdbc/nifiStatelessControl"
        negative = run_case(dist, "negative", negative_value)
        time.sleep(1.0)
        negative_hits = list(listener.hits)

    result = {
        "sample_id": "apache_nifi_stateless__CVE-2021-42550__source_inserted",
        "base_commit": BASE_COMMIT,
        "patch_file": str(CORE_SAMPLE / "patch.diff"),
        "runtime_distribution": str(DIST_TGZ),
        "source_checkout": str(src),
        "runtime_dir": str(dist),
        "assembly": assembly,
        "positive": positive | {"listener_received_count": len(positive_hits), "listener_hits": positive_hits},
        "negative": negative | {"listener_received_count": len(negative_hits), "listener_hits": negative_hits},
    }
    result["status"] = (
        "TP_CONFIRMED"
        if result["positive"]["listener_received_count"] > 0 and result["negative"]["listener_received_count"] == 0
        else "FAILED"
    )
    out = WORK / "evidence" / "runtime-source-verify.json"
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    (WORK / "evidence" / "runtime-source-run.rc").write_text(
        f"RUN_RC={0 if result['status'] == 'TP_CONFIRMED' else 1}\n"
        f"status={result['status']}\n"
        f"positive_listener_received_count={result['positive']['listener_received_count']}\n"
        f"negative_listener_received_count={result['negative']['listener_received_count']}\n"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "TP_CONFIRMED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
