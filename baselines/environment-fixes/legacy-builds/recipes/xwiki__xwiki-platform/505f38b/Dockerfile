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
COPY xwiki-commons-bootstrap /workspace/xwiki-commons

WORKDIR /workspace/repo

RUN cd /workspace/xwiki-commons \
    && mvn -B -q install:install-file -Dfile=xwiki-commons-pom/pom.xml -DpomFile=xwiki-commons-pom/pom.xml -DgroupId=org.xwiki.commons -DartifactId=xwiki-commons-pom -Dversion=15.10.9-SNAPSHOT -Dpackaging=pom \
    && mvn -B -q install:install-file -Dfile=xwiki-commons-tools/xwiki-commons-tool-webjar-handlers/target/xwiki-commons-tool-webjar-handlers-15.10.9.jar -DpomFile=xwiki-commons-tools/xwiki-commons-tool-webjar-handlers/pom.xml -DgroupId=org.xwiki.commons -DartifactId=xwiki-commons-tool-webjar-handlers -Dversion=15.9-SNAPSHOT -Dpackaging=jar \
    && mvn -B -q install:install-file -Dfile=xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-handlers/target/xwiki-commons-tool-xar-handlers-15.10.9.jar -DpomFile=xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-handlers/pom.xml -DgroupId=org.xwiki.commons -DartifactId=xwiki-commons-tool-xar-handlers -Dversion=15.9-SNAPSHOT -Dpackaging=jar \
    && mvn -B -N install
