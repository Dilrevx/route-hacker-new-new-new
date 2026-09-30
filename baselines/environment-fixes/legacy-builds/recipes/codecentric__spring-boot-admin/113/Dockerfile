FROM route-hacker-base:tools-78932d2e-iris
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.9.8/bin:$PATH
COPY output/intermediates/iris-repos/codecentric__spring-boot-admin /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -e -U -DskipTests package
