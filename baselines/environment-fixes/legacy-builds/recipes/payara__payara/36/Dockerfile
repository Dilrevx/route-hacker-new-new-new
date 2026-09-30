FROM route-hacker-base:tools-78932d2e-iris

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Configure Maven proxy, mirrors, and plugin repositories
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol><host>172.17.0.1</host><port>2905</port><nonProxyHosts>nexus.payara.fish|raw.github.com</nonProxyHosts></proxy></proxies>
  <mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror></mirrors>
  <profiles>
    <profile>
      <id>payara-plugin-repos</id>
      <activation><activeByDefault>true</activeByDefault></activation>
      <pluginRepositories>
        <pluginRepository>
          <id>payara-nexus-artifacts-plugins</id>
          <url>https://nexus.payara.fish/repository/payara-artifacts</url>
        </pluginRepository>
        <pluginRepository>
          <id>payara-patched-externals-plugins</id>
          <url>https://raw.github.com/payara/Payara_PatchedProjects/master</url>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
</settings>
XML

# Create and install dummy jaxr-ra artifact (no longer available in any repo)
RUN mkdir -p /tmp/dummy-rar/META-INF && \
    echo 'Dummy JAXR RA for build' > /tmp/dummy-rar/README.txt && \
    printf '<?xml version="1.0" encoding="UTF-8"?>\n<connector xmlns="http://java.sun.com/xml/ns/j2ee">\n  <display-name>JAXR RA</display-name>\n  <vendor-name>Oracle</vendor-name>\n  <specification-version>1.5</specification-version>\n  <eis-type>JAXR</eis-type>\n  <resourceadapter-version>1.0</resourceadapter-version>\n</connector>\n' > /tmp/dummy-rar/META-INF/ra.xml && \
    cd /tmp/dummy-rar && \
    zip -r /tmp/jaxr-ra-JAXR_RA_20091012.rar . && \
    mvn install:install-file -Dfile=/tmp/jaxr-ra-JAXR_RA_20091012.rar -DgroupId=jaxr-ra -DartifactId=jaxr-ra -Dversion=JAXR_RA_20091012 -Dpackaging=rar && \
    rm -rf /tmp/dummy-rar

COPY output/intermediates/iris-repos/payara__payara /workspace/repo

WORKDIR /workspace/repo

# Reorder repositories: try Nexus before slow patched-externals
RUN python3 <<'PYEOF'
import re
with open('pom.xml', 'r') as f:
    content = f.read()
patched_start = '<repository>\n            <id>payara-patched-externals</id>'
patched_end = '</repository>'
nexus_start = '<repository>\n            <id>payara-nexus-artifacts</id>'
nexus_end = '</repository>'
p_start = content.find(patched_start)
p_end = content.find(patched_end, p_start) + len(patched_end)
n_start = content.find(nexus_start)
n_end = content.find(nexus_end, n_start) + len(nexus_end)
if p_start < n_start:
    patched_block = content[p_start:p_end]
    nexus_block = content[n_start:n_end]
    content = content[:p_start] + nexus_block + content[p_end:n_start] + patched_block + content[n_end:]
with open('pom.xml', 'w') as f:
    f.write(content)
PYEOF

# Fix Module ambiguity with java.lang.Module in JDK 9+
RUN for f in $(grep -rln "import com\.sun\.enterprise\.config\.serverbeans\.\*" nucleus appserver api 2>/dev/null); do \
  if grep -n "\bModule\b" "$f" | grep -v "import\|//\s*import\|\.Module\|//.*Module" | grep -q ":"; then \
    sed -i "s/import com\.sun\.enterprise\.config\.serverbeans\.\*;/import com.sun.enterprise.config.serverbeans.Module;\nimport com.sun.enterprise.config.serverbeans.*;/" "$f"; \
  fi; \
done

# Skip domain creation in distribution modules (requires running server)
RUN sed -i 's|<phase>process-resources</phase>|<phase>none</phase>|' \
    nucleus/distributions/payara-minimal/pom.xml \
    appserver/distributions/pom.xml \
    appserver/distributions/payara-web/pom.xml \
    appserver/distributions/payara/pom.xml \
    appserver/distributions/payara-web-ml/pom.xml \
    appserver/distributions/payara-ml/pom.xml

RUN mvn -B -DskipTests install
