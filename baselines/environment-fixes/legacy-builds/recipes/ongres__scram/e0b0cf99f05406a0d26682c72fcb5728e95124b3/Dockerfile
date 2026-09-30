FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Disable the container's default Maven mirror/proxy settings so builds resolve from central.
RUN printf '<settings/>\n' > /root/.m2/settings.xml

COPY ongres__scram /workspace/repo
WORKDIR /workspace/repo
RUN ./mvnw -B -DskipTests install
