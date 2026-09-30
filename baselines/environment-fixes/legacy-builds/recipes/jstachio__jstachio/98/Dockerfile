FROM route-hacker-base:tools-78932d2e-iris
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven/bin:$PATH
COPY output/intermediates/iris-repos/jstachio__jstachio /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests -Dmaven.javadoc.skip=true clean package
