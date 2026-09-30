FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Configure Maven with aliyun mirror (no proxy)
RUN mkdir -p /root/.m2 && \
    printf '%s\n' '<settings><mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror></mirrors></settings>' > /root/.m2/settings.xml

COPY netty__netty /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests install \
    -pl '!io.netty:netty-transport-native-epoll,!io.netty:netty-transport-native-kqueue,!io.netty:netty-resolver-dns-native-macos,!io.netty:netty-testsuite-native,!io.netty:netty-testsuite-native-image,!io.netty:netty-testsuite-native-image-client,!io.netty:netty-testsuite-native-image-client-runtime-init,!io.netty:netty-testsuite-autobahn,!io.netty:netty-testsuite-http2,!io.netty:netty-testsuite-osgi,!io.netty:netty-testsuite-shading,!io.netty:netty-transport-native-unix-common-tests,!io.netty:netty-microbench,!io.netty:netty-example,!io.netty:netty-all'
