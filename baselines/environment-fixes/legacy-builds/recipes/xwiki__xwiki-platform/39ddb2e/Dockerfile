FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies>
    <proxy>
      <id>main</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>127.0.0.1</host>
      <port>7890</port>
    </proxy>
  </proxies>
  <mirrors>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
  </mirrors>
</settings>
XML

COPY output/intermediates/benchmark-repos/xwiki__xwiki-platform /workspace/repo
COPY xwiki-commons-bootstrap /workspace/xwiki-commons-bootstrap

WORKDIR /workspace/repo

RUN set -eux; \
    git config --global --add safe.directory /workspace/repo; \
    git config --global --add safe.directory /workspace/xwiki-commons-bootstrap; \
    if [ -f .mvn/extensions.xml ]; then mv .mvn/extensions.xml .mvn/extensions.xml.disabled; fi; \
    if [ -f /workspace/xwiki-commons-bootstrap/.mvn/extensions.xml ]; then mv /workspace/xwiki-commons-bootstrap/.mvn/extensions.xml /workspace/xwiki-commons-bootstrap/.mvn/extensions.xml.disabled; fi; \
    printf '%s\n' \
      '<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
      '  <modelVersion>4.0.0</modelVersion>' \
      '  <groupId>tmp</groupId>' \
      '  <artifactId>tmp</artifactId>' \
      '  <version>1</version>' \
      '</project>' > /tmp/empty-pom.xml; \
    REQUIRED=$(grep -A3 'xwiki-commons-pom' pom.xml | grep '<version>' | head -1 | sed 's/.*<version>\(.*\)<\/version>.*/\1/'); \
    sed -i "s|<version>15.9-SNAPSHOT</version>|<version>${REQUIRED}</version>|g; s|<commons.version>15.9-SNAPSHOT</commons.version>|<commons.version>${REQUIRED}</commons.version>|g" /workspace/repo/xwiki-commons-pom/pom.xml; \
    cd /workspace/repo/xwiki-commons-pom && mvn -B -q -f /tmp/empty-pom.xml install:install-file -Dfile=/workspace/repo/xwiki-commons-pom/pom.xml -DpomFile=/workspace/repo/xwiki-commons-pom/pom.xml -DgroupId=org.xwiki.commons -DartifactId=xwiki-commons-pom -Dversion=${REQUIRED} -Dpackaging=pom; \
    cd /workspace/xwiki-commons-bootstrap && mvn -B -DskipTests -pl xwiki-commons-tools/xwiki-commons-tool-pom,xwiki-commons-tools/xwiki-commons-tool-extension-plugin,xwiki-commons-tools/xwiki-commons-tool-webjar-handlers,xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-handlers,xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-plugin,xwiki-commons-tools/xwiki-commons-tool-test/xwiki-commons-tool-test-simple -am install

RUN set -eux; \
    for art in xwiki-commons-tool-pom xwiki-commons-tool-extension-plugin xwiki-commons-tool-webjar-handlers xwiki-commons-tool-xar-handlers xwiki-commons-tool-xar-plugin xwiki-commons-tool-test-simple; do \
      case "$art" in \
        xwiki-commons-tool-pom) \
          src=/root/.m2/repository/org/xwiki/commons/xwiki-commons-tool-pom/15.10.9/xwiki-commons-tool-pom-15.10.9.pom; \
          packaging=pom; \
          ;; \
        xwiki-commons-tool-extension-plugin) \
          src=/workspace/xwiki-commons-bootstrap/xwiki-commons-tools/xwiki-commons-tool-extension-plugin/target/xwiki-commons-tool-extension-plugin-15.10.9.jar; \
          packaging=jar; \
          ;; \
        xwiki-commons-tool-webjar-handlers) \
          src=/workspace/xwiki-commons-bootstrap/xwiki-commons-tools/xwiki-commons-tool-webjar-handlers/target/xwiki-commons-tool-webjar-handlers-15.10.9.jar; \
          packaging=jar; \
          ;; \
        xwiki-commons-tool-xar-handlers) \
          src=/workspace/xwiki-commons-bootstrap/xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-handlers/target/xwiki-commons-tool-xar-handlers-15.10.9.jar; \
          packaging=jar; \
          ;; \
        xwiki-commons-tool-xar-plugin) \
          src=/workspace/xwiki-commons-bootstrap/xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-plugin/target/xwiki-commons-tool-xar-plugin-15.10.9.jar; \
          packaging=jar; \
          ;; \
        xwiki-commons-tool-test-simple) \
          src=/workspace/xwiki-commons-bootstrap/xwiki-commons-tools/xwiki-commons-tool-test/xwiki-commons-tool-test-simple/target/xwiki-commons-tool-test-simple-15.10.9.jar; \
          packaging=jar; \
          ;; \
      esac; \
      printf '%s\n' \
        '<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven.xsd">' \
        '  <modelVersion>4.0.0</modelVersion>' \
        '  <groupId>org.xwiki.commons</groupId>' \
        "  <artifactId>${art}</artifactId>" \
        '  <version>13.2-SNAPSHOT</version>' \
        "  <packaging>${packaging}</packaging>" \
        '</project>' > /tmp/${art}-snapshot.pom; \
      mvn -B -q -f /tmp/empty-pom.xml install:install-file -Dfile="$src" -DpomFile=/tmp/${art}-snapshot.pom -DgroupId=org.xwiki.commons -DartifactId=${art} -Dversion=13.2-SNAPSHOT -Dpackaging=${packaging}; \
    done; \
    cd /workspace/repo && mvn -B -Dxwiki.enforcer.skip=true -N install
