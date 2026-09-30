FROM route-hacker-base:tools-78932d2e
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies>
    <proxy>
      <id>main</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>172.17.0.1</host>
      <port>2905</port>
    </proxy>
  </proxies>
  <profiles>
    <profile>
      <id>fit2cloud</id>
      <repositories>
        <repository>
          <id>fit2cloud-public</id>
          <url>https://repository.fit2cloud.com/content/groups/public/</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>fit2cloud-public</id>
          <url>https://repository.fit2cloud.com/content/groups/public/</url>
          <releases><enabled>true</enabled></releases>
          <snapshots><enabled>false</enabled></snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>fit2cloud</activeProfile>
  </activeProfiles>
  <mirrors>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
  </mirrors>
</settings>
XML

COPY output/intermediates/benchmark-repos/metersphere__metersphere /workspace/repo
WORKDIR /workspace/repo
RUN ./mvnw -B -U -DskipTests install
