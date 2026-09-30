#!/usr/bin/env bash
set -euo pipefail

WORK=/data/lhq/workspace/source-runtime-verify/apache_knox__CVE-2021-44228__source_inserted
REPO=/data/lhq/workspace/apache-vuln-dataset/data/repos/knox
MVN="$WORK/tools/apache-maven-3.9.9/bin/mvn"
M2="$WORK/.m2"
RUNTIME="$WORK/runtime"
HOME_DIR="$RUNTIME/gateway-home"

rm -rf "$HOME_DIR"
mkdir -p "$HOME_DIR/bin" "$HOME_DIR/conf" "$HOME_DIR/logs" "$HOME_DIR/pids" "$HOME_DIR/data" "$HOME_DIR/dep" "$HOME_DIR/deployments" "$HOME_DIR/services" "$HOME_DIR/lib" "$HOME_DIR/ext"
cp -a "$REPO/gateway-release/home/conf/." "$HOME_DIR/conf/"
mkdir -p "$HOME_DIR/conf/META-INF/services"
cp "$REPO/gateway-release/src/main/resources/META-INF/services/org.apache.knox.gateway.services.GatewayServices" \
  "$HOME_DIR/conf/META-INF/services/org.apache.knox.gateway.services.GatewayServices"

python3 - "$HOME_DIR/conf/gateway-site.xml" <<'PY'
import sys
from pathlib import Path
import xml.etree.ElementTree as ET

path = Path(sys.argv[1])
tree = ET.parse(path)
root = tree.getroot()
props = {p.findtext("name"): p for p in root.findall("property")}

def set_prop(name, value):
    p = props.get(name)
    if p is None:
        p = ET.SubElement(root, "property")
        ET.SubElement(p, "name").text = name
        ET.SubElement(p, "value")
        props[name] = p
    v = p.find("value")
    if v is None:
        v = ET.SubElement(p, "value")
    v.text = value

remote_alias = props.get("gateway.service.alias.impl")
if remote_alias is not None:
    root.remove(remote_alias)

for name, value in {
    "gateway.port": "18443",
    "gateway.path": "gateway",
    "ssl.enabled": "false",
    "default.app.topology.name": "sandbox",
    "gateway.port.mapping.enabled": "false",
    "gateway.remote.config.monitor.client": "false",
    "gateway.remote.alias.service.enabled": "false",
}.items():
    set_prop(name, value)

tree.write(path, encoding="UTF-8", xml_declaration=True)
PY

cd "$REPO"

cp "$REPO/gateway-server-launcher/target/gateway-server-launcher-3.0.0-SNAPSHOT.jar" "$HOME_DIR/bin/gateway.jar"
while IFS= read -r jar; do
  cp "$jar" "$HOME_DIR/lib/"
done < <(find "$REPO" -mindepth 2 -maxdepth 3 -path "*/target/*.jar" -type f | sort)

if [[ -d "$M2" ]]; then
  while IFS= read -r jar; do
    cp "$jar" "$HOME_DIR/dep/"
  done < <(find "$M2" -type f -name "*.jar" | sort)
elif [[ -d /data/lhq/.m2/repository ]]; then
  while IFS= read -r jar; do
    cp "$jar" "$HOME_DIR/dep/"
  done < <(find /data/lhq/.m2/repository -type f -name "*.jar" | sort)
fi

# The verification repository may contain jars from unrelated old builds.
# Keep the runtime classpath deterministic for dependencies that otherwise
# break Knox startup when multiple versions are present in the flat dep dir.
find "$HOME_DIR/dep" -maxdepth 1 -type f \( \
  -name "commons-cli-1.2.jar" -o \
  -name "slf4j-api-1.*.jar" -o \
  -name "slf4j-jdk14-1.*.jar" -o \
  -name "jcl-over-slf4j-1.*.jar" -o \
  -name "log4j-slf4j2-impl-*.jar" \
\) -delete

find "$REPO/gateway-service-definitions/target/classes/services" -maxdepth 1 -mindepth 1 -type d -exec cp -a {} "$HOME_DIR/services/" \;
cp "$REPO/gateway-release/home/conf/topologies/sandbox.xml" "$HOME_DIR/conf/topologies/sandbox.xml"
printf "%s\n" "$HOME_DIR" > "$RUNTIME/gateway-home.path"
find "$HOME_DIR/lib" "$HOME_DIR/dep" -maxdepth 1 -type f -name "*.jar" | sort > "$RUNTIME/runtime-jars.txt"
sha256sum "$HOME_DIR/lib/gateway-server-3.0.0-SNAPSHOT.jar" > "$WORK/evidence/runtime-gateway-server-jar.sha256"
printf "assembled runtime at %s\n" "$HOME_DIR"
