FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
# JDK 17 is required for this GlassFish 6.2.5 build
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.9.8/bin:$PATH
COPY output/intermediates/iris-repos/eclipse-ee4j__glassfish /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -e -U -DskipTests package
