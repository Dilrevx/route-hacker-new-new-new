FROM route-hacker-base:tools-78932d2e

# Project requires JDK 11+ (enforcer rule)
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Remove inaccessible proxy from Maven settings
RUN mkdir -p /root/.m2 && \
    echo '<settings><mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror></mirrors></settings>' > /root/.m2/settings.xml

COPY codehaus-plexus__plexus-utils /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests compile
