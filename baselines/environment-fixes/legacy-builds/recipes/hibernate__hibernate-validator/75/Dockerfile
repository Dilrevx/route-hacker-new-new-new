FROM route-hacker-base:tools-78932d2e-iris

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH

# Configure Maven proxy for host networking
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
  <mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror></mirrors>
</settings>
XML

COPY output/intermediates/iris-repos/hibernate__hibernate-validator /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -e -U -DskipTests package
