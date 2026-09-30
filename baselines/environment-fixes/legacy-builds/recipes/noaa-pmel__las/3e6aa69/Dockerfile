FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /workspace/repo/WebContent/WEB-INF/lib && \
    curl -L --fail -o /workspace/repo/WebContent/WEB-INF/lib/ant-launcher-1.10.5.jar https://repo1.maven.org/maven2/org/apache/ant/ant-launcher/1.10.5/ant-launcher-1.10.5.jar

COPY noaa-pmel__las /workspace/repo
WORKDIR /workspace/repo
RUN /usr/lib/jvm/temurin-8-jdk-amd64/bin/java -cp /usr/lib/jvm/temurin-8-jdk-amd64/lib/tools.jar:WebContent/WEB-INF/lib/ant-1.10.5.jar:WebContent/WEB-INF/lib/ant-launcher-1.10.5.jar org.apache.tools.ant.Main -Djakarta.lib=/workspace/repo/WebContent/WEB-INF/lib -Djakarta.home=/workspace/repo -f build.xml.in compile
