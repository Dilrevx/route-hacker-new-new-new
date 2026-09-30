FROM route-hacker-base:tools-78932d2e-iris

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Maven config with proxy, Aliyun mirror, and JBoss public repository
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
  <mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror></mirrors>
  <profiles>
    <profile>
      <id>jboss-public-repository</id>
      <repositories>
        <repository>
          <id>jboss-public-repository-group</id>
          <name>JBoss Public Maven Repository Group</name>
          <url>https://repository.jboss.org/nexus/content/groups/public/</url>
          <layout>default</layout>
          <releases><enabled>true</enabled><updatePolicy>never</updatePolicy></releases>
          <snapshots><enabled>true</enabled><updatePolicy>never</updatePolicy></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>jboss-public-repository-group</id>
          <name>JBoss Public Maven Repository Group</name>
          <url>https://repository.jboss.org/nexus/content/groups/public/</url>
          <layout>default</layout>
          <releases><enabled>true</enabled><updatePolicy>never</updatePolicy></releases>
          <snapshots><enabled>true</enabled><updatePolicy>never</updatePolicy></snapshots>
        </pluginRepository>
      </pluginRepositories>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>jboss-public-repository</activeProfile>
  </activeProfiles>
</settings>
XML

# Create and install a dummy keycloak-admin-ui artifact (needed by dependencies/admin-ui wrapper)
RUN mkdir -p /tmp/dummy-admin-ui && cat > /tmp/dummy-admin-ui/pom.xml <<'POM'
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>org.keycloak</groupId>
  <artifactId>keycloak-admin-ui</artifactId>
  <version>999-SNAPSHOT</version>
  <packaging>jar</packaging>
</project>
POM
RUN mkdir -p /tmp/dummy-admin-ui/src/main/java/org/keycloak/admin/ui && \
    echo 'package org.keycloak.admin.ui; public class Dummy {}' > /tmp/dummy-admin-ui/src/main/java/org/keycloak/admin/ui/Dummy.java && \
    cd /tmp/dummy-admin-ui && mvn -B install -DskipTests && \
    rm -rf /tmp/dummy-admin-ui

COPY output/intermediates/benchmark-repos/keycloak__keycloak /workspace/repo
WORKDIR /workspace/repo

RUN mvn -B -DskipTests -U clean install
