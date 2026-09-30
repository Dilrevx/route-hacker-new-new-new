FROM route-hacker-base:tools-78932d2e
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
ENV MAVEN_OPTS=-Dhttps.protocols=TLSv1.2\ -Djdk.tls.client.protocols=TLSv1.2
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
      <id>all-http-to-jenkinsci</id>
      <mirrorOf>external:http:*</mirrorOf>
      <url>https://repo.jenkins-ci.org/public/</url>
    </mirror>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
  </mirrors>
</settings>
XML
RUN set -eux; \
    tmp=/tmp/artifacts; \
    mkdir -p "$tmp"; \
    curl -fsSL https://repo.jenkins-ci.org/public/org/jenkins-ci/main/remoting/2.23/remoting-2.23.jar -o "$tmp/remoting-2.23.jar"; \
    curl -fsSL https://repo.jenkins-ci.org/public/org/jenkins-ci/main/remoting/2.23/remoting-2.23.pom -o "$tmp/remoting-2.23.pom"; \
    mvn -B -q install:install-file -DgroupId=org.jenkins-ci.main -DartifactId=remoting -Dversion=2.23 -Dpackaging=jar -Dfile="$tmp/remoting-2.23.jar" -DpomFile="$tmp/remoting-2.23.pom"; \
    curl -fsSL https://repo.jenkins-ci.org/public/org/jvnet/localizer/localizer/1.14/localizer-1.14.jar -o "$tmp/localizer-1.14.jar"; \
    curl -fsSL https://repo.jenkins-ci.org/public/org/jvnet/localizer/localizer/1.14/localizer-1.14.pom -o "$tmp/localizer-1.14.pom"; \
    mvn -B -q install:install-file -DgroupId=org.jvnet.localizer -DartifactId=localizer -Dversion=1.14 -Dpackaging=jar -Dfile="$tmp/localizer-1.14.jar" -DpomFile="$tmp/localizer-1.14.pom"
COPY output/intermediates/benchmark-repos/jenkinsci__jenkins /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -U -DskipTests -pl cli -am -DskipITs compile -rf :cli
