FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN cd /tmp && \
    rm -rf gradle-8.10 gradle-8.10-bin.zip && \
    curl -fL --retry 10 --retry-delay 5 --retry-all-errors \
      -o gradle-8.10-bin.zip \
      https://downloads.gradle.org/distributions/gradle-8.10-bin.zip && \
    unzip -q gradle-8.10-bin.zip

COPY plantuml__plantuml /workspace/repo
WORKDIR /workspace/repo

RUN export JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64 && \
    export PATH=$JAVA_HOME/bin:$PATH && \
    /tmp/gradle-8.10/bin/gradle -x test -x javaDoc compileJava
