FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH
COPY docker-support/m2-cache/spring-cloud__spring-cloud-config /root/.m2/repository
COPY output/intermediates/iris-repos/spring-cloud__spring-cloud-config /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -e -U -DskipTests -Dcheckstyle.skip=true package
