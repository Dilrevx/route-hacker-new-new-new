FROM route-hacker-base:tools-78932d2e-iris
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
COPY output/intermediates/iris-repos/apache__commons-text /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests compile
