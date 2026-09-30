FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=/opt/maven-3.9.8/bin:$JAVA_HOME/bin:$PATH

# Pre-populate Maven local repository with pre-cached artifacts
COPY assets/route_hacker/build-context/m2-repo /root/.m2/repository

# Maven proxy settings
RUN mkdir -p /root/.m2 && printf '%s\n' '<settings>' '<proxies>' '<proxy><id>main</id><active>true</active><protocol>http</protocol><host>127.0.0.1</host><port>7890</port></proxy>' '</proxies>' '</settings>' > /root/.m2/settings.xml

# Workaround: admin-ui module requires external SNAPSHOT artifact that doesn't exist
RUN mkdir -p /root/.m2/repository/org/keycloak/keycloak-dependencies-admin-ui-wrapper/999-SNAPSHOT && \
    echo '<?xml version="1.0" encoding="UTF-8"?><project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>org.keycloak</groupId><artifactId>keycloak-dependencies-admin-ui-wrapper</artifactId><version>999-SNAPSHOT</version><packaging>pom</packaging></project>' \
    > /root/.m2/repository/org/keycloak/keycloak-dependencies-admin-ui-wrapper/999-SNAPSHOT/keycloak-dependencies-admin-ui-wrapper-999-SNAPSHOT.pom && \
    mkdir -p /root/.m2/repository/org/keycloak/keycloak-admin-ui/999-SNAPSHOT && \
    echo '<?xml version="1.0" encoding="UTF-8"?><project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>org.keycloak</groupId><artifactId>keycloak-admin-ui</artifactId><version>999-SNAPSHOT</version><packaging>jar</packaging></project>' \
    > /root/.m2/repository/org/keycloak/keycloak-admin-ui/999-SNAPSHOT/keycloak-admin-ui-999-SNAPSHOT.pom && \
    mkdir -p /tmp/jar-contents && cd /tmp/jar-contents && \
    jar cf /root/.m2/repository/org/keycloak/keycloak-admin-ui/999-SNAPSHOT/keycloak-admin-ui-999-SNAPSHOT.jar . && \
    rm -rf /tmp/jar-contents

COPY output/intermediates/benchmark-repos/keycloak__keycloak /workspace/repo
WORKDIR /workspace/repo

# Simplify admin-ui POM to remove external SNAPSHOT repository
RUN mkdir -p dependencies/admin-ui && printf '%s\n' '<?xml version="1.0"?>' '<project xmlns="http://maven.apache.org/POM/4.0.0">' '    <parent>' '        <artifactId>keycloak-dependencies-parent</artifactId>' '        <groupId>org.keycloak</groupId>' '        <version>999-SNAPSHOT</version>' '    </parent>' '    <modelVersion>4.0.0</modelVersion>' '    <artifactId>keycloak-dependencies-admin-ui-wrapper</artifactId>' '    <packaging>jar</packaging>' '    <name>Keycloak Admin UI BOM wrapper</name>' '    <description>BOM wrapper for Admin UI to limit Sonatype snapshot repository to admin-ui</description>' '</project>' > dependencies/admin-ui/pom.xml

# Pre-download large artifacts that may fail during Maven build
RUN mkdir -p /root/.m2/repository/org/infinispan/infinispan-core/14.0.7.Final && \
    curl -sL --retry 5 -o /tmp/infinispan-core.jar "https://repo.maven.apache.org/maven2/org/infinispan/infinispan-core/14.0.7.Final/infinispan-core-14.0.7.Final.jar" && \
    mv /tmp/infinispan-core.jar /root/.m2/repository/org/infinispan/infinispan-core/14.0.7.Final/infinispan-core-14.0.7.Final.jar && \
    curl -sL --retry 5 -o /tmp/infinispan-core.pom "https://repo.maven.apache.org/maven2/org/infinispan/infinispan-core/14.0.7.Final/infinispan-core-14.0.7.Final.pom" && \
    mv /tmp/infinispan-core.pom /root/.m2/repository/org/infinispan/infinispan-core/14.0.7.Final/infinispan-core-14.0.7.Final.pom

# Build with retry - use a loop to handle transient network issues
RUN for i in 1 2 3; do \
      mvn -B -DskipTests clean package && break; \
      echo "Build attempt $i failed, retrying..."; \
      sleep 10; \
    done
