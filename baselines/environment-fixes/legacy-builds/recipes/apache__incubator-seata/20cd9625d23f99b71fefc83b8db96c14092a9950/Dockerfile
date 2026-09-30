FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Clean Maven settings (remove proxy/mirror config from base image)
RUN rm -f /root/.m2/settings.xml && mkdir -p /root/.m2 && echo '<settings></settings>' > /root/.m2/settings.xml

COPY apache__incubator-seata /workspace/repo
WORKDIR /workspace/repo
RUN ./mvnw -B -DskipTests compile
