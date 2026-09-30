FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /tmp && printf '<settings>\n</settings>\n' >/tmp/no-proxy-settings.xml

COPY aiven-open__bigquery-connector-for-apache-kafka /workspace/repo
WORKDIR /workspace/repo

RUN mvn -B -s /tmp/no-proxy-settings.xml -DskipTests compile
