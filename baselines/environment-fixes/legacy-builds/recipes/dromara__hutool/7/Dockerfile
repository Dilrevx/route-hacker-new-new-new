FROM route-hacker-base:tools-78932d2e-iris

# Set correct JAVA_HOME for JDK 8 (required by hutool 4.x with source/target 7)
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH

COPY output/intermediates/iris-repos/dromara__hutool /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -e -U -DskipTests package
