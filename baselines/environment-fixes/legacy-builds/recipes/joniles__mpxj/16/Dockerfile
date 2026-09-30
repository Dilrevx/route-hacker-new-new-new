FROM route-hacker-base:tools-78932d2e-iris

# Set correct JAVA_HOME for JDK 8
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH

# Gradle proxy configuration
RUN mkdir -p /root/.gradle && printf 'systemProp.http.proxyHost=127.0.0.1\nsystemProp.http.proxyPort=7890\nsystemProp.https.proxyHost=127.0.0.1\nsystemProp.https.proxyPort=7890\n' > /root/.gradle/gradle.properties

COPY output/intermediates/iris-repos/joniles__mpxj /workspace/repo
WORKDIR /workspace/repo

RUN mvn -B -e -U -DskipTests package
