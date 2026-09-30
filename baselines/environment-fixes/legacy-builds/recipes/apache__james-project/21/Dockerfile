FROM route-hacker-base:tools-78932d2e-iris

# Set JDK 11 (as required by pom.xml <target.jdk>11</target.jdk>)
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# git-commit-id-plugin needs git access; mark repo as safe
RUN git config --global --add safe.directory /workspace/repo

COPY output/intermediates/benchmark-repos/apache__james-project /workspace/repo

WORKDIR /workspace/repo

RUN mvn -B -DskipTests compile
