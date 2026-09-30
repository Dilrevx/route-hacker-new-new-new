FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies>
    <proxy>
      <id>main</id>
      <active>true</active>
      <protocol>http</protocol>
      <host>127.0.0.1</host>
      <port>7890</port>
    </proxy>
  </proxies>
  <mirrors>
    <mirror>
      <id>aliyun-central</id>
      <mirrorOf>central</mirrorOf>
      <url>https://maven.aliyun.com/repository/central</url>
    </mirror>
  </mirrors>
</settings>
XML

RUN mkdir -p /root/.gradle && printf 'systemProp.http.proxyHost=127.0.0.1\nsystemProp.http.proxyPort=7890\nsystemProp.https.proxyHost=127.0.0.1\nsystemProp.https.proxyPort=7890\n' > /root/.gradle/gradle.properties

COPY output/intermediates/benchmark-repos/dataease__dataease /workspace/repo
WORKDIR /workspace/repo

RUN set -e; \
    sed -i '/<repositories>/,/<\/repositories>/d' backend/pom.xml; \
    base=https://mvn.elitescloud.com/nexus/repository/maven-public; \
    mkdir -p /tmp/pentaho; \
    curl -L --retry 3 -o /tmp/pentaho/kettle-core.jar "$base/pentaho-kettle/kettle-core/8.3.0.18-1112/kettle-core-8.3.0.18-1112.jar"; \
    curl -L --retry 3 -o /tmp/pentaho/kettle-engine.jar "$base/pentaho-kettle/kettle-engine/8.3.0.18-1112/kettle-engine-8.3.0.18-1112.jar"; \
    curl -L --retry 3 -o /tmp/pentaho/metastore.jar "$base/pentaho/metastore/8.3.0.18-1112/metastore-8.3.0.18-1112.jar"; \
    curl -L --retry 3 -o /tmp/pentaho/pdi-engine-configuration-impl.jar "$base/org/pentaho/di/plugins/pdi-engine-configuration-impl/8.3.0.7-683/pdi-engine-configuration-impl-8.3.0.7-683.jar"; \
    mvn -q org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file -Dfile=/tmp/pentaho/kettle-core.jar -DgroupId=pentaho-kettle -DartifactId=kettle-core -Dversion=8.3.0.18-1112 -Dpackaging=jar -DgeneratePom=true; \
    mvn -q org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file -Dfile=/tmp/pentaho/kettle-engine.jar -DgroupId=pentaho-kettle -DartifactId=kettle-engine -Dversion=8.3.0.18-1112 -Dpackaging=jar -DgeneratePom=true; \
    mvn -q org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file -Dfile=/tmp/pentaho/metastore.jar -DgroupId=pentaho -DartifactId=metastore -Dversion=8.3.0.18-1112 -Dpackaging=jar -DgeneratePom=true; \
    mvn -q org.apache.maven.plugins:maven-install-plugin:3.1.1:install-file -Dfile=/tmp/pentaho/pdi-engine-configuration-impl.jar -DgroupId=org.pentaho.di.plugins -DartifactId=pdi-engine-configuration-impl -Dversion=8.3.0.7-683 -Dpackaging=jar -DgeneratePom=true; \
    mvn -B -DskipTests install -U
