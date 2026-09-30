#!/usr/bin/env python3
import json
import pathlib
import shutil


sample = pathlib.Path("/data/lhq/workspace/ljl-v1-core/source-insertion/samples/apache_nifi_stateless__CVE-2021-42550__source_inserted")
scratch = pathlib.Path("/data/lhq/workspace/source-runtime-verify/apache_nifi_stateless__CVE-2021-42550__source_inserted/evidence")
evd = sample / "evidence"
evd.mkdir(exist_ok=True)

for name in ["runtime-source-verify.json", "runtime-source-run.rc", "git-apply-check.rc"]:
    src = scratch / name
    if src.exists():
        shutil.copy2(src, evd / name)

result = json.load(open(evd / "runtime-source-verify.json"))
asm = result["assembly"]

(evd / "nifi-stateless-source-runtime-assembly-summary.txt").write_text("\n".join([
    "sample_id=apache_nifi_stateless__CVE-2021-42550__source_inserted",
    f"base_commit={result['base_commit']}",
    f"runtime_distribution={result['runtime_distribution']}",
    f"runtime_dir={result['runtime_dir']}",
    "assembly=patched source resources copied into real nifi-stateless-1.14.0 binary distribution; logback 1.2.3 jars replaced with logback 1.2.7 jars downloaded from Maven Central",
    f"source_bin_sha256={asm['source_bin_sha256']}",
    f"runtime_bin_after_sha256={asm['runtime_bin_after_sha256']}",
    f"source_conf_sha256={asm['source_conf_sha256']}",
    f"runtime_conf_after_sha256={asm['runtime_conf_after_sha256']}",
    f"logback_core_1_2_7_sha256={asm['logback_core_1_2_7_sha256']}",
    f"logback_classic_1_2_7_sha256={asm['logback_classic_1_2_7_sha256']}",
    f"positive_listener_received_count={result['positive']['listener_received_count']}",
    f"negative_listener_received_count={result['negative']['listener_received_count']}",
    f"status={result['status']}",
    "caveat=resource-level source-runtime assembly; full NiFi Maven package was not run in this verifier",
    "",
]))

for key, filename in [
    ("source_bin_sha256", "nifi-stateless-sh-source.sha256"),
    ("runtime_bin_before_sha256", "nifi-stateless-sh-runtime-before.sha256"),
    ("runtime_bin_after_sha256", "nifi-stateless-sh-runtime-after.sha256"),
    ("source_conf_sha256", "stateless-logback-source.sha256"),
    ("runtime_conf_before_sha256", "stateless-logback-runtime-before.sha256"),
    ("runtime_conf_after_sha256", "stateless-logback-runtime-after.sha256"),
]:
    (evd / filename).write_text(asm[key] + "\n")

mp = sample / "metadata.json"
meta = json.load(open(mp))
meta["status"] = "tp_runtime_verified"
meta["build"] = {
    "status": "resource_assembly_verified",
    "command": "python3 /data/lhq/workspace/source-runtime-verify/run_nifi_stateless_source_runtime_probe.py",
    "log": "evidence/runtime-source-verify.json",
    "notes": "Verifier exported the patch-touched source files at the base commit, applied patch.diff, copied patched nifi-stateless.sh and stateless-logback.xml into the real nifi-stateless-1.14.0 binary distribution, and replaced Logback runtime jars with 1.2.7 artifacts. Full NiFi Maven package was not run."
}
meta["verification"] = {
    "status": "tp_runtime_verified",
    "entrypoint": "bin/nifi-stateless.sh --help using patched source resources and Logback 1.2.7 jars inside nifi-stateless-1.14.0 runtime",
    "positive": {
        "input": "STATELESS_REVIEW_JNDI_LOCATION=rmi://127.0.0.1:<listener>/nifiStatelessReview",
        "listener_received_count": result["positive"]["listener_received_count"],
        "returncode": result["positive"]["returncode"],
        "evidence": "evidence/runtime-source-verify.json",
    },
    "negative": {
        "input": "STATELESS_REVIEW_JNDI_LOCATION=java:comp/env/jdbc/nifiStatelessControl",
        "listener_received_count": result["negative"]["listener_received_count"],
        "returncode": result["negative"]["returncode"],
        "evidence": "evidence/runtime-source-verify.json",
    },
    "notes": "Positive run loaded STATELESS_REVIEW_DB from patched stateless-logback.xml and made one RMI connection to the local listener. Negative control loaded the same appender with a java:comp/env value and made zero listener connections.",
}
json.dump(meta, open(mp, "w"), indent=2)
open(mp, "a").write("\n")

readme = sample / "README.md"
text = readme.read_text()
old = """## Status

Current status: `source_patch_created`.

Evidence:

- `evidence/apply-check.log`: clean checkout at the base commit accepts
  `patch.diff` with `git apply --check`.

Build/runtime status:

- Build: not run for this source patch yet.
- Runtime verification: not run for this source patch yet.
- Legacy binary-runtime evidence exists for project and trigger feasibility, but
  it is not used as the TP label for this source-level sample.
"""
new = """## Status

Current status: `tp_runtime_verified`.

Evidence:

- `evidence/apply-check.log`: clean checkout at the base commit accepts
  `patch.diff` with `git apply --check`.
- `evidence/runtime-source-verify.json`: source-runtime positive/negative probe
  result.
- `evidence/runtime-source-run.rc`: compact verifier status.
- `evidence/nifi-stateless-source-runtime-assembly-summary.txt`: source/runtime
  resource hashes and dependency jar hashes.

Build/runtime status:

- Build: resource-level source-runtime assembly verified. The verifier exported
  the patch-touched files at base commit
  `fcbf1d5f975dd984e34f3a543b9480c779b0dc2f`, applied `patch.diff`, copied the
  patched `nifi-stateless.sh` and `stateless-logback.xml` into the real
  `nifi-stateless-1.14.0` binary distribution, and replaced Logback 1.2.3 jars
  with Logback 1.2.7 jars.
- Runtime verification: passed. Positive
  `STATELESS_REVIEW_JNDI_LOCATION=rmi://127.0.0.1:<listener>/nifiStatelessReview`
  caused one local RMI listener connection. Negative
  `STATELESS_REVIEW_JNDI_LOCATION=java:comp/env/jdbc/nifiStatelessControl`
  caused zero listener connections.
- Caveat: full NiFi Maven package was not run in this verifier; this is a
  resource-level source-runtime assembly check for the patched startup script,
  Logback configuration, and vulnerable Logback runtime jars.
"""
if old not in text:
    raise SystemExit("README status block did not match expected text")
readme.write_text(text.replace(old, new))
