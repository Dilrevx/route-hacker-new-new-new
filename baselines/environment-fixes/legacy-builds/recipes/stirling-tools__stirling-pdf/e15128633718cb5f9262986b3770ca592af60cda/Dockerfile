FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

COPY stirling-tools__stirling-pdf /workspace/repo
WORKDIR /workspace/repo
RUN ./gradlew compileJava --no-daemon -x test -x spotlessCheck -x spotlessApply
