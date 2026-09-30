FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Remove proxy from Maven settings so it connects directly
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml << 'SETTINGS'
<settings>
  <mirrors>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
  </mirrors>
</settings>
SETTINGS

COPY wildfirechat__im-server /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests compile
