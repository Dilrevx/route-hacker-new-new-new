FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <mirrors>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
  </mirrors>
</settings>
XML

# Disable Gradle Enterprise build extensions which block offline build
RUN if [ -f /workspace/repo/.mvn/extensions.xml ]; then \
      mv /workspace/repo/.mvn/extensions.xml /workspace/repo/.mvn/extensions.xml.disabled; \
    fi

# Pre-stage xwiki-commons bootstrap source
COPY assets/route_hacker/build-context/xwiki__xwiki-platform/xwiki-commons-bootstrap /workspace/xwiki-commons-bootstrap
COPY xwiki__xwiki-platform /workspace/repo

WORKDIR /workspace/repo

# Step 1: Install xwiki-commons parent POM with version 16.5.0-SNAPSHOT
# The bootstrap source is at 15.10.9; we patch the version to match what xwiki-platform 16.5.0-SNAPSHOT expects
RUN set -eux; \
    if [ -f /workspace/xwiki-commons-bootstrap/.mvn/extensions.xml ]; then \
      mv /workspace/xwiki-commons-bootstrap/.mvn/extensions.xml /workspace/xwiki-commons-bootstrap/.mvn/extensions.xml.disabled; \
    fi; \
    printf '%s\n' \
      '<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
      '  <modelVersion>4.0.0</modelVersion>' \
      '  <groupId>tmp</groupId>' \
      '  <artifactId>tmp</artifactId>' \
      '  <version>1</version>' \
      '</project>' > /tmp/empty-pom.xml; \
    sed 's|<version>15.10.9</version>|<version>16.5.0-SNAPSHOT</version>|g; \
        s|<commons.version>15.10.9</commons.version>|<commons.version>16.5.0-SNAPSHOT</commons.version>|g' \
      /workspace/xwiki-commons-bootstrap/pom.xml > /tmp/xwiki-commons-16.pom; \
    mvn -B -q -f /tmp/empty-pom.xml install:install-file \
      -Dfile=/tmp/xwiki-commons-16.pom \
      -DpomFile=/tmp/xwiki-commons-16.pom \
      -DgroupId=org.xwiki.commons \
      -DartifactId=xwiki-commons \
      -Dversion=16.5.0-SNAPSHOT \
      -Dpackaging=pom

# Step 2: Build xwiki-commons from bootstrap source (needed for dependency artifacts)
RUN set -eux; \
    cd /workspace/xwiki-commons-bootstrap/xwiki-commons; \
    if [ -f .mvn/extensions.xml ]; then \
      mv .mvn/extensions.xml .mvn/extensions.xml.disabled; \
    fi; \
    mvn -B -DskipTests -Dxwiki.enforcer.skip=true -Drevision=16.5.0-SNAPSHOT install

# Step 3: Reinstall all built commons artifacts with consistent version 16.5.0-SNAPSHOT
RUN set -eux; \
    find /root/.m2/repository/org/xwiki -name 'resolver-status.properties' -delete 2>/dev/null || true; \
    find /root/.m2/repository/org/xwiki/commons -name '*.pom' -path '*/15.10.9/*' | while read pomfile; do \
      dir=$(dirname "$pomfile"); \
      artifact_dir=$(dirname "$dir"); \
      artifact_id=$(basename "$artifact_dir"); \
      base=$(basename "$pomfile" .pom); \
      jarfile="$dir/$base.jar"; \
      if [ -f "$jarfile" ]; then \
        mvn -B -q -f /tmp/empty-pom.xml install:install-file \
          -Dfile="$jarfile" \
          -DpomFile="$pomfile" \
          -DgroupId=org.xwiki.commons \
          -DartifactId="$artifact_id" \
          -Dversion=16.5.0-SNAPSHOT \
          -Dpackaging=jar; \
      else \
        mvn -B -q -f /tmp/empty-pom.xml install:install-file \
          -Dfile="$pomfile" \
          -DpomFile="$pomfile" \
          -DgroupId=org.xwiki.commons \
          -DartifactId="$artifact_id" \
          -Dversion=16.5.0-SNAPSHOT \
          -Dpackaging=pom; \
      fi; \
    done

# Step 4: Install synthetic xwiki-commons-pom with missing dependency management
RUN set -eux; \
    printf '%s\n' \
      '<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
      '  <modelVersion>4.0.0</modelVersion>' \
      '  <parent>' \
      '    <groupId>org.xwiki.commons</groupId>' \
      '    <artifactId>xwiki-commons</artifactId>' \
      '    <version>16.5.0-SNAPSHOT</version>' \
      '  </parent>' \
      '  <artifactId>xwiki-commons-pom</artifactId>' \
      '  <version>16.5.0-SNAPSHOT</version>' \
      '  <packaging>pom</packaging>' \
      '  <properties>' \
      '    <commons.version>16.5.0-SNAPSHOT</commons.version>' \
      '  </properties>' \
      '  <dependencyManagement>' \
      '    <dependencies>' \
      '      <dependency>' \
      '        <groupId>jakarta.ws.rs</groupId>' \
      '        <artifactId>jakarta.ws.rs-api</artifactId>' \
      '        <version>3.1.0</version>' \
      '      </dependency>' \
      '      <dependency>' \
      '        <groupId>org.apache.groovy</groupId>' \
      '        <artifactId>groovy</artifactId>' \
      '        <version>4.0.21</version>' \
      '      </dependency>' \
      '    </dependencies>' \
      '  </dependencyManagement>' \
      '</project>' > /tmp/xwiki-commons-pom-16.xml; \
    mvn -B -q -f /tmp/empty-pom.xml install:install-file \
      -Dfile=/tmp/xwiki-commons-pom-16.xml \
      -DpomFile=/tmp/xwiki-commons-pom-16.xml \
      -DgroupId=org.xwiki.commons \
      -DartifactId=xwiki-commons-pom \
      -Dversion=16.5.0-SNAPSHOT \
      -Dpackaging=pom

# Step 5: Install xwiki-platform parent POM
RUN mvn -B -Dxwiki.enforcer.skip=true -N install
