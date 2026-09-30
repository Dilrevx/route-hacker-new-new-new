FROM route-hacker-base:tools-78932d2e-iris

# Proxy configuration (base image already sets HTTP_PROXY/HTTPS_PROXY)
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

# Set JDK 8
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH

# Configure Maven proxy
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
</settings>
XML

# Copy repository
COPY output/intermediates/iris-repos/kubernetes-client__java /workspace/repo

WORKDIR /workspace/repo

# Build with Maven
RUN mvn -B -DskipTests clean package
