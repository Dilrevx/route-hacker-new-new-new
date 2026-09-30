FROM route-hacker-cache/jenkinsci__docker-commons-plugin:59-m2cache
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH
COPY output/intermediates/iris-repos/jenkinsci__docker-commons-plugin /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -e -DskipTests package
