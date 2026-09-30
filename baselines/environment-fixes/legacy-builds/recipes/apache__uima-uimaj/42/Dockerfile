FROM route-hacker-base:tools-78932d2e-iris

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH

# Restore pre-cached Maven repository from successful build
COPY docker-support/m2-repo.tar.gz /tmp/m2-repo.tar.gz
RUN tar xzf /tmp/m2-repo.tar.gz -C /root/.m2 && rm /tmp/m2-repo.tar.gz

# Configure Maven with proxy only
RUN mkdir -p /root/.m2 && cat > /root/.m2/settings.xml <<'XML'
<settings>
  <proxies><proxy><id>main</id><active>true</active><protocol>http</protocol>
    <host>127.0.0.1</host><port>7890</port></proxy></proxies>
</settings>
XML

COPY output/intermediates/iris-repos/apache__uima-uimaj /workspace/repo
WORKDIR /workspace/repo

# Build core UIMA modules (exclude Eclipse plugins and docbooks)
RUN mvn -B -DskipTests clean package \
    -pl '!aggregate-uimaj-eclipse-plugins,!uimaj-ep-debug,!uimaj-ep-jcasgen,!uimaj-ep-configurator,!uimaj-ep-pear-packager,!uimaj-ep-launcher,!uimaj-ep-cas-editor,!uimaj-ep-cas-editor-ide,!uimaj-ep-runtime,!uimaj-eclipse-feature-tools,!uimaj-eclipse-feature-runtime,!aggregate-uimaj-docbooks,!uima-docbook-overview-and-setup,!uima-docbook-references,!uima-docbook-tools,!uima-docbook-tutorials-and-users-guides,!uima-doc-v3-users-guide'
