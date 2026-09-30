FROM route-hacker-base:tools-78932d2e-iris
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH
COPY output/intermediates/iris-repos/apache__dolphinscheduler /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests -Dspotless.skip=true clean package
