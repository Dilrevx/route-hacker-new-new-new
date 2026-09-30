FROM route-hacker-base:tools-78932d2e-iris

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

# JDK 8 for DSpace 5.10 (Java 7 target)
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH

# Configure Maven proxy
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
</settings>
XML

COPY output/intermediates/benchmark-repos/DSpace__DSpace /workspace/repo

WORKDIR /workspace/repo

RUN mvn -B -DskipTests install
