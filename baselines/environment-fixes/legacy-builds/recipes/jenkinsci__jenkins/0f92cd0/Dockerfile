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
    curl -fsSLo "$tmp/stapler-groovy-1.169.jar" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/kohsuke/stapler/stapler-groovy/1.169/stapler-groovy-1.169.jar; \
    curl -fsSLo "$tmp/stapler-groovy-1.169.pom" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/kohsuke/stapler/stapler-groovy/1.169/stapler-groovy-1.169.pom; \
    mvn -B -q install:install-file -DgroupId=org.kohsuke.stapler -DartifactId=stapler-groovy -Dversion=1.169 -Dpackaging=jar -Dfile="$tmp/stapler-groovy-1.169.jar" -DpomFile="$tmp/stapler-groovy-1.169.pom"; \
    curl -fsSLo "$tmp/stapler-jelly-1.169.jar" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/kohsuke/stapler/stapler-jelly/1.169/stapler-jelly-1.169.jar; \
    curl -fsSLo "$tmp/stapler-jelly-1.169.pom" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/kohsuke/stapler/stapler-jelly/1.169/stapler-jelly-1.169.pom; \
    mvn -B -q install:install-file -DgroupId=org.kohsuke.stapler -DartifactId=stapler-jelly -Dversion=1.169 -Dpackaging=jar -Dfile="$tmp/stapler-jelly-1.169.jar" -DpomFile="$tmp/stapler-jelly-1.169.pom"; \
    curl -fsSLo "$tmp/trilead-ssh2-build214-jenkins-1.jar" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/jenkins-ci/trilead-ssh2/build214-jenkins-1/trilead-ssh2-build214-jenkins-1.jar; \
    curl -fsSLo "$tmp/trilead-ssh2-build214-jenkins-1.pom" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/jenkins-ci/trilead-ssh2/build214-jenkins-1/trilead-ssh2-build214-jenkins-1.pom; \
    mvn -B -q install:install-file -DgroupId=org.jenkins-ci -DartifactId=trilead-ssh2 -Dversion=build214-jenkins-1 -Dpackaging=jar -Dfile="$tmp/trilead-ssh2-build214-jenkins-1.jar" -DpomFile="$tmp/trilead-ssh2-build214-jenkins-1.pom"; \
    curl -fsSLo "$tmp/commons-jelly-1.1-jenkins-20110627.jar" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/jenkins-ci/commons-jelly/1.1-jenkins-20110627/commons-jelly-1.1-jenkins-20110627.jar; \
    curl -fsSLo "$tmp/commons-jelly-1.1-jenkins-20110627.pom" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/jenkins-ci/commons-jelly/1.1-jenkins-20110627/commons-jelly-1.1-jenkins-20110627.pom; \
    mvn -B -q install:install-file -DgroupId=org.jenkins-ci -DartifactId=commons-jelly -Dversion=1.1-jenkins-20110627 -Dpackaging=jar -Dfile="$tmp/commons-jelly-1.1-jenkins-20110627.jar" -DpomFile="$tmp/commons-jelly-1.1-jenkins-20110627.pom"; \
    curl -fsSLo "$tmp/remoting-2.53.4.jar" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/jenkins-ci/main/remoting/2.53.4/remoting-2.53.4.jar; \
    curl -fsSLo "$tmp/remoting-2.53.4.pom" --retry 5 --retry-all-errors --retry-delay 2 --http1.1 https://repo.jenkins-ci.org/public/org/jenkins-ci/main/remoting/2.53.4/remoting-2.53.4.pom; \
    mvn -B -q install:install-file -DgroupId=org.jenkins-ci.main -DartifactId=remoting -Dversion=2.53.4 -Dpackaging=jar -Dfile="$tmp/remoting-2.53.4.jar" -DpomFile="$tmp/remoting-2.53.4.pom"
COPY output/intermediates/benchmark-repos/jenkinsci__jenkins /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -U -DskipTests -pl cli -am -DskipITs compile
