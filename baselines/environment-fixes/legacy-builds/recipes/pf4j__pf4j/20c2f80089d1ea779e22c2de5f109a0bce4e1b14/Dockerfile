FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Clear any proxy/mirror settings that may interfere with Maven Central access
RUN mkdir -p /root/.m2 && echo '<settings></settings>' > /root/.m2/settings.xml

COPY pf4j__pf4j /workspace/repo
WORKDIR /workspace/repo
RUN ./mvnw -B -DskipTests install
