FROM route-hacker-base:tools-78932d2e

# msgpack-java targets Java 1.8 source/target level; JDK 17 handles it fine
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

COPY msgpack__msgpack-java /workspace/repo
WORKDIR /workspace/repo
RUN ./sbt compile
