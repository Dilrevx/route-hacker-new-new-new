FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=/opt/maven-3.5.0/bin:$JAVA_HOME/bin:$PATH
COPY output/intermediates/iris-repos/x-stream__xstream /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests compile
