FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.9.8/bin:$PATH

# Configure Maven proxy settings
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
</settings>
XML

COPY output/intermediates/iris-repos/xwiki__xwiki-commons /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests package
