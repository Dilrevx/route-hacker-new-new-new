FROM route-hacker-base:tools-78932d2e-iris

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

# Set JDK 8 and Maven 3.5.0
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=/opt/maven-3.5.0/bin:$JAVA_HOME/bin:$PATH

# Configure Maven proxy and mirrors
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
  <mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf>
    <url>https://maven.aliyun.com/repository/central</url></mirror></mirrors>
</settings>
XML

COPY output/intermediates/iris-repos/jenkinsci__perfecto-plugin /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests clean package
