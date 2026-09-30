FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Maven settings with JBoss public repository (required for Keycloak dependencies)
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml << 'XML'
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 http://maven.apache.org/xsd/settings-1.0.0.xsd">
  <localRepository>/root/.m2/repository</localRepository>
  <profiles>
    <profile>
      <id>jboss-public-repository</id>
      <repositories>
        <repository>
          <id>central</id>
          <url>https://repo.maven.apache.org/maven2</url>
          <releases><enabled>true</enabled><updatePolicy>never</updatePolicy></releases>
          <snapshots><enabled>true</enabled><updatePolicy>never</updatePolicy></snapshots>
        </repository>
        <repository>
          <id>jboss-public-repository-group</id>
          <url>https://repository.jboss.org/nexus/content/groups/public/</url>
          <releases><enabled>true</enabled><updatePolicy>never</updatePolicy></releases>
          <snapshots><enabled>true</enabled><updatePolicy>never</updatePolicy></snapshots>
        </repository>
      </repositories>
      <pluginRepositories>
        <pluginRepository>
          <id>central</id>
          <url>https://repo.maven.apache.org/maven2</url>
          <releases><enabled>true</enabled><updatePolicy>never</updatePolicy></releases>
          <snapshots><enabled>true</enabled><updatePolicy>never</updatePolicy></snapshots>
        </pluginRepository>
        <pluginRepository>
          <id>jboss-public-repository-group</id>
          <url>https://repository.jboss.org/nexus/content/groups/public/</url>
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

COPY keycloak__keycloak /workspace/repo
WORKDIR /workspace/repo
RUN mv .mvn/extensions.xml .mvn/extensions.xml.disabled 2>/dev/null || true && ./mvnw -B -s /root/.m2/settings.xml -pl quarkus/deployment,quarkus/dist -am -DskipTests -DskipProtoLock=true clean install
