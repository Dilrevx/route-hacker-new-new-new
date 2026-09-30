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

WORKDIR /workspace/repo

RUN git clone --depth 1 --branch xwiki-commons-15.9 https://github.com/xwiki/xwiki-commons.git /tmp/xwiki-commons \
    && cd /tmp/xwiki-commons \
    && mvn -B -DskipTests -pl xwiki-commons-tools/xwiki-commons-tool-webjar-handlers,xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-handlers -am install \
    && mvn -B -q install:install-file -Dfile=xwiki-commons-tools/xwiki-commons-tool-webjar-handlers/target/xwiki-commons-tool-webjar-handlers-15.9.jar -DpomFile=xwiki-commons-tools/xwiki-commons-tool-webjar-handlers/pom.xml -DgroupId=org.xwiki.commons -DartifactId=xwiki-commons-tool-webjar-handlers -Dversion=15.9-SNAPSHOT -Dpackaging=jar \
    && mvn -B -q install:install-file -Dfile=xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-handlers/target/xwiki-commons-tool-xar-handlers-15.9.jar -DpomFile=xwiki-commons-tools/xwiki-commons-tool-xar/xwiki-commons-tool-xar-handlers/pom.xml -DgroupId=org.xwiki.commons -DartifactId=xwiki-commons-tool-xar-handlers -Dversion=15.9-SNAPSHOT -Dpackaging=jar \
    && mvn -B -DskipTests install -f xwiki-commons-pom/pom.xml \
    && mvn -B -N install
