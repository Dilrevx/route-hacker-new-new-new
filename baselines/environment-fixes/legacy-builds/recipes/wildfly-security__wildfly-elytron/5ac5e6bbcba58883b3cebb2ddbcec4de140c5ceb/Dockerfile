FROM route-hacker-base:tools-78932d2e

# Maven settings: no proxy, mirror central to aliyun, ensure JBoss repo access
RUN mkdir -p /root/.m2 && \
    cat > /root/.m2/settings.xml << 'XMLEOF'
<settings>
  <mirrors>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
    <mirror>
      <id>jboss-public</id>
      <mirrorOf>public-jboss</mirrorOf>
      <url>https://repository.jboss.org/nexus/content/groups/public-jboss/</url>
    </mirror>
  </mirrors>
</settings>
XMLEOF

COPY wildfly-security__wildfly-elytron /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests install
