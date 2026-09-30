FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

# Maven proxy and mirror settings - override base image defaults
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
  <mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror></mirrors>
</settings>
XML

# Set correct JDK and Maven versions
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.9.8/bin:$PATH

# Pre-populate Maven local repository to minimize network downloads
COPY assets/route_hacker/build-context/_m2_cache /root/.m2/repository

COPY output/intermediates/iris-repos/apache__nifi /workspace/repo
WORKDIR /workspace/repo

# Build with no-swagger-ui profile (skip downloading Swagger UI from GitHub);
# not using --offline because some BOM POMs have different versions in cache
RUN mvn -B -e -DskipTests package -P no-swagger-ui
