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
    printf '%s\n' \
      '<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
      '  <modelVersion>4.0.0</modelVersion>' \
      '  <groupId>tmp</groupId>' \
      '  <artifactId>tmp</artifactId>' \
      '  <version>1</version>' \
      '</project>' > /tmp/empty-pom.xml

RUN set -eux; \
    mvn -B -q -f /tmp/empty-pom.xml install:install-file \
      -Dfile=/workspace/xwiki-commons-bootstrap/pom.xml \
      -DpomFile=/workspace/xwiki-commons-bootstrap/pom.xml \
      -DgroupId=org.xwiki.commons \
      -DartifactId=xwiki-commons-pom \
      -Dversion=17.0.0-SNAPSHOT \
      -Dpackaging=pom

RUN set -eux; \
    if [ -f .mvn/extensions.xml ]; then mv .mvn/extensions.xml .mvn/extensions.xml.disabled; fi; \
    mvn -B -q -Dxwiki.enforcer.skip=true -N install
