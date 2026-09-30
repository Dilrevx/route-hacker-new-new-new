FROM route-hacker-base:tools-78932d2e
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.m2 /root/.gradle \
 && cat > /root/.m2/settings.xml <<'XML'
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
</settings>
XML

COPY output/intermediates/benchmark-repos/keycloak__keycloak /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -U -DskipTests -DskipTestsuite -pl integration/client-cli/client-registration-cli -am package
