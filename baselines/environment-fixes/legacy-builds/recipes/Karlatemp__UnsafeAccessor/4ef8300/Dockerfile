FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.gradle && printf 'systemProp.http.proxyHost=127.0.0.1\nsystemProp.http.proxyPort=7890\nsystemProp.https.proxyHost=127.0.0.1\nsystemProp.https.proxyPort=7890\n' > /root/.gradle/gradle.properties

COPY output/intermediates/benchmark-repos/Karlatemp__UnsafeAccessor /workspace/repo
WORKDIR /workspace/repo

RUN mkdir -p impl/jdks && cat > impl/jdks/gradle.properties <<'EOF'
jdk8.name=Temurin 8
jdk8.loc=/usr/lib/jvm/temurin-8-jdk-amd64
jdk9.name=Temurin 17
jdk9.loc=/usr/lib/jvm/temurin-17-jdk-amd64
jdk17.name=Temurin 17
jdk17.loc=/usr/lib/jvm/temurin-17-jdk-amd64
EOF

RUN java -cp gradle/wrapper/gradle-wrapper.jar org.gradle.wrapper.GradleWrapperMain :impl.testunit:doBuild
