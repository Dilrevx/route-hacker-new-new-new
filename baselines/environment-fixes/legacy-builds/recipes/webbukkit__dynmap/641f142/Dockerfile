FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.gradle && printf 'systemProp.http.proxyHost=127.0.0.1\nsystemProp.http.proxyPort=7890\nsystemProp.https.proxyHost=127.0.0.1\nsystemProp.https.proxyPort=7890\n' > /root/.gradle/gradle.properties

COPY output/intermediates/benchmark-repos/webbukkit__dynmap /workspace/repo
WORKDIR /workspace/repo

RUN cat > settings.gradle <<'EOF'
rootProject.name = 'dynmap-common'
include ':DynmapCore'
include ':DynmapCoreAPI'

project(':DynmapCore').projectDir = "$rootDir/DynmapCore" as File
project(':DynmapCoreAPI').projectDir = "$rootDir/DynmapCoreAPI" as File
EOF

RUN ./gradlew --no-daemon -q build -x test
