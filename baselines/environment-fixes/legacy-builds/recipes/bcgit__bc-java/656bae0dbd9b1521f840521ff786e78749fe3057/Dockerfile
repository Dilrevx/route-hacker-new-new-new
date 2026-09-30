FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
ENV BC_JDK8=/usr/lib/jvm/temurin-8-jdk-amd64
ENV BC_JDK11=/usr/lib/jvm/temurin-11-jdk-amd64
ENV BC_JDK17=/usr/lib/jvm/temurin-17-jdk-amd64
ENV BC_JDK21=/usr/lib/jvm/temurin-21-jdk-amd64

COPY output/intermediates/pipeline-repos/bcgit__bc-java /workspace/repo
WORKDIR /workspace/repo
RUN ./gradlew compileJava -x test -x javadoc -x compileJava25Java --no-daemon
