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
  <mirrors>
    <mirror>
      <id>jboss-public-repository-group-https</id>
      <mirrorOf>jboss-public-repository-group</mirrorOf>
      <url>https://repository.jboss.org/nexus/repository/public/</url>
    </mirror>
    <mirror>
      <id>sonatype-https</id>
      <mirrorOf>sonatype</mirrorOf>
      <url>https://oss.sonatype.org/content/repositories/snapshots</url>
    </mirror>
    <mirror>
      <id>sonatype-public-https</id>
      <mirrorOf>Sonatype-public</mirrorOf>
      <url>https://oss.sonatype.org/content/groups/public/</url>
    </mirror>
    <mirror>
      <id>jboss-fs-public-https</id>
      <mirrorOf>jboss-fs-public</mirrorOf>
      <url>https://repository.jboss.org/nexus/repository/fs-public/</url>
    </mirror>
    <mirror>
      <id>apache-snapshots-https</id>
      <mirrorOf>apache.snapshots</mirrorOf>
      <url>https://repository.apache.org/snapshots</url>
    </mirror>
    <mirror>
      <id>restlet-org-https</id>
      <mirrorOf>restlet.org</mirrorOf>
      <url>https://maven.restlet.talend.com/</url>
    </mirror>
    <mirror>
      <id>fusesource-m2-https</id>
      <mirrorOf>fusesource.m2</mirrorOf>
      <url>https://repo.fusesource.com/maven2</url>
    </mirror>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
  </mirrors>
</settings>
XML

COPY output/intermediates/benchmark-repos/uberfire__uberfire /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests compile
