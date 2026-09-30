FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
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
  <profiles>
    <profile>
      <id>xwiki</id>
      <repositories>
        <repository>
          <id>xwiki-releases</id>
          <url>https://nexus-snapshots.xwiki.org/repository/public-proxy</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
        <repository>
          <id>xwiki-snapshots</id>
          <url>https://nexus-snapshots.xwiki.org/repository/snapshots/</url>
          <releases><enabled>false</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>xwiki-releases</id>
          <url>https://nexus-snapshots.xwiki.org/repository/public-proxy</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </pluginRepository>
        <pluginRepository>
          <id>xwiki-snapshots</id>
          <url>https://nexus-snapshots.xwiki.org/repository/snapshots/</url>
          <releases><enabled>false</enabled></releases>
          <snapshots><enabled>true</enabled></snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>xwiki</activeProfile>
  </activeProfiles>
</settings>
XML

COPY output/intermediates/benchmark-repos/xwiki-contrib__oidc /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests compile
