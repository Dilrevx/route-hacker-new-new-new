FROM route-hacker-base:tools-134326bb

ENV HTTP_PROXY=http://172.17.0.1:2905
ENV HTTPS_PROXY=http://172.17.0.1:2905
ENV http_proxy=http://172.17.0.1:2905
ENV https_proxy=http://172.17.0.1:2905

# ActiveMQ builds against Java 17 with Maven source/target 11/17.
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=/usr/lib/jvm/temurin-17-jdk-amd64/bin:${PATH}

COPY output/intermediates/benchmark-repos/apache__activemq /workspace/repo
WORKDIR /workspace/repo

RUN mvn -B -DskipTests install

RUN codeql database create /codeql-db \
        --language=java-kotlin \
        --source-root=/workspace/repo \
        --command="mvn -B -DskipTests install" \
        --overwrite

RUN mkdir -p /codeql-results

RUN codeql database analyze /codeql-db \
        --format=sarifv2.1.0 \
        --output=/codeql-results/results.sarif \
        -- /opt/codeql/qlpacks/codeql/java-queries/1.11.0/codeql-suites/java-security-and-quality.qls
