FROM route-hacker-base:tools-78932d2e

# Set correct JAVA_HOME for JDK 17 (required by pom.xml maven.compiler.source=17)
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Fix Maven settings: remove proxy that causes timeouts (no proxy available in this environment)
RUN cat > /root/.m2/settings.xml << 'XMLEOF'
<settings>
  <mirrors>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
  </mirrors>
</settings>
XMLEOF

COPY thingsboard__thingsboard /workspace/repo
WORKDIR /workspace/repo

# Build all Java modules except ui-ngx (frontend) and msa/web-ui (depends on ui-ngx jar)
RUN mvn -B -DskipTests compile -pl '!ui-ngx,!msa/web-ui'
