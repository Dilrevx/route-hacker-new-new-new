FROM route-hacker-base:tools-50757a05

ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Override base image Maven settings to remove proxy
RUN mkdir -p /root/.m2 && \
    echo '<settings><mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror></mirrors></settings>' > /root/.m2/settings.xml

COPY 1panel-dev__cordyscrm /workspace/repo
WORKDIR /workspace/repo

# Build (exclude frontend module which requires Node.js/pnpm)
RUN mvn -B -DskipTests compile -pl '!frontend'

# Clean compiled output so CodeQL can trace a fresh compilation
RUN mvn -B -DskipTests clean -pl '!frontend' -q && \
    codeql database create /codeql-db \
        --language=java-kotlin \
        --source-root=/workspace/repo \
        --command="mvn -B -DskipTests compile -pl backend/framework,backend/crm,backend/app" \
        --overwrite

RUN QLPACK_DIR=$(find /opt/codeql/qlpacks/codeql/java-queries -maxdepth 1 -type d -name '[0-9]*' | sort -V | tail -1) && \
    mkdir -p /codeql-results && \
    codeql database analyze /codeql-db \
        --format=sarifv2.1.0 \
        --output=/codeql-results/results.sarif \
        "${QLPACK_DIR}/codeql-suites/java-security-and-quality.qls"
