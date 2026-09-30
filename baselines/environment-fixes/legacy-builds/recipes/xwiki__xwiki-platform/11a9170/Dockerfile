FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

COPY output/intermediates/benchmark-repos/xwiki__xwiki-platform /workspace/repo

WORKDIR /workspace/repo

RUN cd xwiki-commons-pom \
    && sed -i 's/<version>15.0-SNAPSHOT<\/version>/<version>15.2-SNAPSHOT<\/version>/g; s/<commons.version>15.0-SNAPSHOT<\/commons.version>/<commons.version>15.2-SNAPSHOT<\/commons.version>/g' pom.xml \
    && mvn -B install

RUN perl -0pi -e 's#\n  <build>\n    <extensions>.*?</extensions>\n    <pluginManagement>#\n  <build>\n    <pluginManagement>#s' pom.xml \
    && mvn -B -N install
