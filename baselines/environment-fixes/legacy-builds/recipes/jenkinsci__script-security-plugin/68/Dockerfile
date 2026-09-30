FROM route-hacker-base:tools-78932d2e-iris
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven/bin:$PATH
COPY output/intermediates/iris-repos/jenkinsci__script-security-plugin /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests clean package
