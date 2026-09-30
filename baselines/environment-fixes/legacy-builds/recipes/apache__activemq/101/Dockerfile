FROM route-hacker-base:tools-78932d2e-iris

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

# ActiveMQ 5.15.8 builds with JDK 8 (source/target 1.8)
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=/usr/lib/jvm/temurin-8-jdk-amd64/bin:/opt/maven-3.5.0/bin:${PATH}

# Configure Maven proxy and mirror
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
  <mirrors>
    <mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror>
  </mirrors>
</settings>
XML

COPY output/intermediates/benchmark-repos/apache__activemq /workspace/repo
WORKDIR /workspace/repo

RUN mvn -B -DskipTests package
