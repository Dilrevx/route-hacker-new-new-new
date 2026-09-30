FROM route-hacker-base:tools-78932d2e
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV http_proxy=http://127.0.0.1:7890
ENV https_proxy=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
RUN mkdir -p /root/.gradle && printf 'systemProp.http.proxyHost=127.0.0.1\nsystemProp.http.proxyPort=7890\nsystemProp.https.proxyHost=127.0.0.1\nsystemProp.https.proxyPort=7890\nsystemProp.http.nonProxyHosts=localhost|127.*|[::1]\nsystemProp.https.protocols=TLSv1,TLSv1.1,TLSv1.2\n' > /root/.gradle/gradle.properties
COPY output/intermediates/benchmark-repos/line__armeria /workspace/repo
WORKDIR /workspace/repo
RUN ./gradlew --no-daemon -PofflineJavadoc -PnoLint :core:compileJava
