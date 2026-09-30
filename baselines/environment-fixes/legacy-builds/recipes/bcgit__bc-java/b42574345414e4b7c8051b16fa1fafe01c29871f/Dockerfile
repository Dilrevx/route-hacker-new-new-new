FROM route-hacker-base:tools-50757a05

ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
ENV BC_JDK8=/usr/lib/jvm/temurin-8-jdk-amd64
ENV BC_JDK11=/usr/lib/jvm/temurin-11-jdk-amd64
ENV BC_JDK17=/usr/lib/jvm/temurin-17-jdk-amd64
ENV BC_JDK21=/usr/lib/jvm/temurin-21-jdk-amd64

COPY bcgit__bc-java /workspace/repo

WORKDIR /workspace/repo
RUN cp .gradle-cache/gradle-9.1.0-bin.zip /tmp/ && \
    sed -i 's|distributionUrl=https\\://services.gradle.org/distributions/gradle-9.1.0-bin.zip|distributionUrl=file\\:///tmp/gradle-9.1.0-bin.zip|' gradle/wrapper/gradle-wrapper.properties && \
    ./gradlew compileJava -x test -x javadoc -x compileJava25Java --no-daemon --console=plain && \
    rm -rf .gradle-cache

# CodeQL: create database (clean first so compilation is traced)
RUN ./gradlew clean --no-daemon --console=plain && \
    codeql database create /codeql-db \
        --language=java-kotlin \
        --source-root=/workspace/repo \
        --command="./gradlew compileJava -x test -x javadoc -x compileJava25Java --no-daemon --console=plain" \
        --overwrite

# CodeQL: run analysis
RUN mkdir -p /codeql-results && \
    codeql database analyze /codeql-db \
        --format=sarifv2.1.0 \
        --output=/codeql-results/results.sarif \
        -- codeql/java-queries:codeql-suites/java-security-and-quality.qls
