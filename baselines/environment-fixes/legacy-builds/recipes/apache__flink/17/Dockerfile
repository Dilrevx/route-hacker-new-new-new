FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH

# Configure Maven proxy for host-network build
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
  <mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf>
    <url>https://maven.aliyun.com/repository/central</url></mirror></mirrors>
</settings>
XML

COPY output/intermediates/iris-repos/apache__flink /workspace/repo
WORKDIR /workspace/repo

# Exclude modules that fail due to npm integrity issues (flink-runtime-web)
# and unreachable S3 repo (flink-connector-kinesis)
RUN mvn -B -e -U -DskipTests package \
    -pl '!org.apache.flink:flink-runtime-web_2.11,!org.apache.flink:flink-connector-kinesis_2.11'
