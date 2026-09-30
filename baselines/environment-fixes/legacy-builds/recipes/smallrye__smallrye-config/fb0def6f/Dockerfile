FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

COPY output/intermediates/benchmark-repos/smallrye__smallrye-config /workspace/repo
WORKDIR /workspace/repo

RUN mvn -B -DskipTests -Dformat.skip=true -Dimpsort.skip=true compile
