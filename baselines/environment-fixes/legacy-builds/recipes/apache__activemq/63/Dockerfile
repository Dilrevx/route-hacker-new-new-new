FROM route-hacker-base:tools-78932d2e-iris

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

# ActiveMQ 5.11.0 builds with JDK 8 (source/target 1.7)
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=/usr/lib/jvm/temurin-8-jdk-amd64/bin:/opt/maven-3.5.0/bin:${PATH}

# Configure Maven proxy and mirrors
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
  <mirrors>
    <mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror>
  </mirrors>
</settings>
XML

# Pre-populate Eclipse Paho mqtt-client 0.4.0 artifact (needed by activemq-mqtt)
# The original spring.io/plugins-release repo is dead, so we fetch from a mirror
RUN mkdir -p /root/.m2/repository/org/eclipse/paho/mqtt-client/0.4.0 && \
    mkdir -p /root/.m2/repository/org/eclipse/paho/java-parent/0.4.0 && \
    curl -sL -o /root/.m2/repository/org/eclipse/paho/mqtt-client/0.4.0/mqtt-client-0.4.0.jar \
      https://maven-eu.nuxeo.org/nexus/content/repositories/thirdparty-releases/org/eclipse/paho/mqtt-client/0.4.0/mqtt-client-0.4.0.jar && \
    curl -sL -o /root/.m2/repository/org/eclipse/paho/mqtt-client/0.4.0/mqtt-client-0.4.0.pom \
      https://maven-eu.nuxeo.org/nexus/content/repositories/thirdparty-releases/org/eclipse/paho/mqtt-client/0.4.0/mqtt-client-0.4.0.pom && \
    curl -sL -o /root/.m2/repository/org/eclipse/paho/java-parent/0.4.0/java-parent-0.4.0.pom \
      https://maven-eu.nuxeo.org/nexus/content/repositories/thirdparty-releases/org/eclipse/paho/java-parent/0.4.0/java-parent-0.4.0.pom

COPY output/intermediates/benchmark-repos/apache__activemq /workspace/repo
WORKDIR /workspace/repo

# Fix dead spring.io plugins-release repo URL in activemq-mqtt pom.xml
RUN sed -i 's|http://repo.spring.io/plugins-release|https://repo1.maven.org/maven2|' /workspace/repo/activemq-mqtt/pom.xml

# Build all modules except the karaf-itest (depends on dead HTTP-only repos)
RUN mvn -B -DskipTests -pl '!activemq-karaf-itest' package
