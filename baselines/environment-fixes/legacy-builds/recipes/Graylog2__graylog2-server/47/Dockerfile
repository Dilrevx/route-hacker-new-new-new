FROM route-hacker-base:tools-78932d2e-iris

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.9.8/bin:$PATH

COPY output/intermediates/benchmark-repos/Graylog2__graylog2-server /workspace/repo

WORKDIR /workspace/repo

# Skip enforcer plugin because Maven 3.9.x is incompatible with enforcer-plugin:3.0.0
RUN mvn -B -Denforcer.skip=true -DskipTests -Dskip.web.build compile
