FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Maven settings: mirror all repos through Aliyun HTTPS to avoid HTTP blocking
RUN mkdir -p /root/.m2 && echo '<settings><mirrors><mirror><id>aliyun-mirror</id><mirrorOf>*</mirrorOf><url>https://maven.aliyun.com/repository/public</url></mirror></mirrors></settings>' > /root/.m2/settings.xml

COPY elunez__eladmin /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests install
