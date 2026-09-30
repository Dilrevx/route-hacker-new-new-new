FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

COPY jcthiele__openxrechnungtoolbox /workspace/repo
WORKDIR /workspace/repo

RUN printf '%s\n' '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd"></settings>' > /tmp/empty-settings.xml
RUN mvn -B -s /tmp/empty-settings.xml -DskipTests -P linux_64bit compile
