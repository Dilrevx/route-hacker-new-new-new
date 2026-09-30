FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

COPY output/intermediates/benchmark-repos/seam2__jboss-seam /workspace/repo
WORKDIR /workspace/repo

RUN mvn -B -s build/settings.xml -DskipTests -pl jboss-seam -am compile
