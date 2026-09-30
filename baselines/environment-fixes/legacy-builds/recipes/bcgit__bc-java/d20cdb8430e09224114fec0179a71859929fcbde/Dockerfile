FROM route-hacker-base:tools-50757a05

ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
ENV BC_JDK8=/usr/lib/jvm/temurin-8-jdk-amd64
ENV BC_JDK11=/usr/lib/jvm/temurin-11-jdk-amd64
ENV BC_JDK17=/usr/lib/jvm/temurin-17-jdk-amd64
ENV BC_JDK21=/usr/lib/jvm/temurin-21-jdk-amd64

COPY bcgit__bc-java /workspace/repo
WORKDIR /workspace/repo

# Pre-cache Gradle distribution from bundled copy
RUN mkdir -p /root/.gradle/wrapper/dists/gradle-9.1.0-bin/9agqghryom9wkf8r80qlhnts3 && \
    cp -r .gradle-cache/gradle-9.1.0-bin/9agqghryom9wkf8r80qlhnts3/* \
        /root/.gradle/wrapper/dists/gradle-9.1.0-bin/9agqghryom9wkf8r80qlhnts3/ && \
    rm -rf .gradle-cache

RUN ./gradlew compileJava -x test -x javadoc -x compileJava25Java --no-daemon --console=plain

# CodeQL database creation
RUN cd /workspace/repo && ./gradlew clean --no-daemon --console=plain && \
    codeql database create /codeql-db \
    --language=java-kotlin \
    --source-root=/workspace/repo \
    --command="./gradlew compileJava -x test -x javadoc -x compileJava25Java --no-daemon --console=plain" \
    --overwrite

RUN mkdir -p /codeql-results && \
    QLPACK_DIR=$(ls -d /opt/codeql/qlpacks/codeql/java-queries/*/codeql-suites 2>/dev/null | head -1) && \
    codeql database analyze /codeql-db \
    --format=sarifv2.1.0 \
    --output=/codeql-results/results.sarif \
    "${QLPACK_DIR}/java-security-and-quality.qls"
