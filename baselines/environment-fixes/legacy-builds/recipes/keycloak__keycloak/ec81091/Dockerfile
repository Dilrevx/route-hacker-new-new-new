FROM route-hacker-base:tools-78932d2e
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.m2/repository/org/keycloak/keycloak-admin-ui/999-SNAPSHOT \
 && cat > /root/.m2/repository/org/keycloak/keycloak-admin-ui/999-SNAPSHOT/keycloak-admin-ui-999-SNAPSHOT.pom <<'XML'
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.keycloak</groupId>
  <artifactId>keycloak-admin-ui</artifactId>
  <version>999-SNAPSHOT</version>
  <packaging>jar</packaging>
</project>
XML
RUN mkdir -p /tmp/keycloak-admin-ui-empty \
 && jar cf /root/.m2/repository/org/keycloak/keycloak-admin-ui/999-SNAPSHOT/keycloak-admin-ui-999-SNAPSHOT.jar -C /tmp/keycloak-admin-ui-empty .

COPY output/intermediates/benchmark-repos/keycloak__keycloak /workspace/repo
WORKDIR /workspace/repo
RUN ./mvnw -B -U -DskipTests -DskipTestsuite -pl integration/client-cli/client-registration-cli -am package
