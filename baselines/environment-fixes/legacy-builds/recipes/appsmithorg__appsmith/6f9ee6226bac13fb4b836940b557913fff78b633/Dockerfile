FROM route-hacker-base:tools-78932d2e

# Set correct JAVA_HOME for JDK 17
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Remove proxy settings that route through 127.0.0.1:2905 (unreachable)
RUN rm -f /root/.m2/settings.xml

COPY appsmithorg__appsmith /workspace/repo
WORKDIR /workspace/repo/app/server
RUN mvn -B -DskipTests -Dmaven.test.skip=true clean install
